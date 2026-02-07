"""
hunter.py - Autonomous bug hunting orchestrator for BountyLedger.

The agentic brain that ties together:
- HackerOne scope fetching
- Recon (subfinder → httpx → katana)
- Parameter harvesting
- Canary URL deployment via interactsh
- Callback monitoring
- Report generation

Usage:
    from bounty_ledger import hunter
    results = hunter.hunt("shopify", dry_run=False)
"""

import time
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from . import database as db
from . import recon
from . import harvester
from . import guardrails
from . import interactsh
from . import hackerone


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class HuntConfig:
    """Configuration for a hunt session."""
    program_handle: str
    max_subdomains: int = 500
    crawl_depth: int = 3
    rate_limit: int = 10
    monitor_duration: int = 300  # 5 minutes
    poll_interval: int = 5
    min_confidence: float = 0.5
    dry_run: bool = False
    output_dir: Optional[Path] = None
    
    def __post_init__(self):
        if self.output_dir is None:
            self.output_dir = Path(__file__).parent.parent / "recon_output"


@dataclass
class HuntPhaseResult:
    """Result of a single hunt phase."""
    phase: str
    success: bool
    message: str
    data: dict = field(default_factory=dict)
    duration_seconds: float = 0.0


@dataclass
class HuntResult:
    """Complete results of a hunt session."""
    program: str
    started_at: str = ""
    completed_at: str = ""
    phases: list[HuntPhaseResult] = field(default_factory=list)
    domains_scanned: int = 0
    sinks_found: int = 0
    tests_deployed: int = 0
    hits_confirmed: int = 0
    
    @property
    def success(self) -> bool:
        return all(p.success for p in self.phases)
    
    def save(self, output_dir: Path) -> Path:
        """Save hunt results to JSON."""
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = output_dir / f"hunt_{self.program}_{timestamp}.json"
        
        data = {
            "program": self.program,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "domains_scanned": self.domains_scanned,
            "sinks_found": self.sinks_found,
            "tests_deployed": self.tests_deployed,
            "hits_confirmed": self.hits_confirmed,
            "phases": [
                {
                    "phase": p.phase,
                    "success": p.success,
                    "message": p.message,
                    "duration_seconds": p.duration_seconds,
                }
                for p in self.phases
            ],
        }
        
        filepath.write_text(json.dumps(data, indent=2))
        return filepath


# ============================================================================
# Hunt Engine
# ============================================================================

def hunt(
    config: HuntConfig,
    on_phase: Optional[Callable[[str, str], None]] = None,
) -> HuntResult:
    """
    Execute a full autonomous hunt against a HackerOne program.
    
    Pipeline:
        1. Fetch scope from HackerOne
        2. Run recon on each in-scope domain
        3. Harvest parameters from discovered URLs
        4. Deploy canary URLs via interactsh
        5. Monitor for callbacks
    
    Args:
        config: Hunt configuration
        on_phase: Optional callback for progress updates (phase_name, message)
    
    Returns:
        HuntResult with complete hunt data
    """
    result = HuntResult(program=config.program_handle)
    result.started_at = datetime.now().isoformat()
    
    def _notify(phase: str, msg: str):
        if on_phase:
            on_phase(phase, msg)
    
    # Ensure database is ready
    db.init_db()
    
    # ========================================================================
    # Phase 1: Fetch Scope
    # ========================================================================
    _notify("scope", "Fetching program scope from HackerOne...")
    phase_start = time.time()
    
    try:
        h1_client = hackerone.HackerOneClient.from_config()
        
        if h1_client.is_configured:
            program_info = h1_client.get_program_scope(config.program_handle)
            domains = program_info.bounty_domains or program_info.web_domains
        else:
            # Fall back to config.json scope
            config_path = Path(__file__).parent.parent / "config.json"
            if config_path.exists():
                with open(config_path) as f:
                    cfg = json.load(f)
                domains = cfg.get("allowed_scope", [])
            else:
                domains = []
        
        if not domains:
            result.phases.append(HuntPhaseResult(
                phase="scope",
                success=False,
                message="No in-scope domains found. Configure HackerOne API or add domains to config.json.",
                duration_seconds=time.time() - phase_start,
            ))
            result.completed_at = datetime.now().isoformat()
            return result
        
        result.domains_scanned = len(domains)
        result.phases.append(HuntPhaseResult(
            phase="scope",
            success=True,
            message=f"Found {len(domains)} in-scope domains",
            data={"domains": domains},
            duration_seconds=time.time() - phase_start,
        ))
    
    except Exception as e:
        result.phases.append(HuntPhaseResult(
            phase="scope",
            success=False,
            message=f"Error fetching scope: {e}",
            duration_seconds=time.time() - phase_start,
        ))
        result.completed_at = datetime.now().isoformat()
        return result
    
    # ========================================================================
    # Phase 2: Recon
    # ========================================================================
    _notify("recon", f"Running recon on {len(domains)} domains...")
    phase_start = time.time()
    
    all_urls = []
    recon_errors = []
    
    for domain in domains:
        # Clean domain pattern for recon
        clean_domain = domain.lstrip("*.")
        
        if config.dry_run:
            _notify("recon", f"[DRY RUN] Would scan: {clean_domain}")
            continue
        
        try:
            _notify("recon", f"Scanning: {clean_domain}")
            recon_result = recon.full_recon(
                clean_domain,
                output_dir=config.output_dir,
                max_subdomains=config.max_subdomains,
                crawl_depth=config.crawl_depth,
                rate_limit=config.rate_limit,
            )
            all_urls.extend(recon_result.crawled_urls)
            recon_errors.extend(recon_result.errors)
        except Exception as e:
            recon_errors.append(f"{clean_domain}: {e}")
    
    result.phases.append(HuntPhaseResult(
        phase="recon",
        success=True,
        message=f"Discovered {len(all_urls)} URLs across {len(domains)} domains",
        data={"url_count": len(all_urls), "errors": recon_errors},
        duration_seconds=time.time() - phase_start,
    ))
    
    if config.dry_run:
        result.completed_at = datetime.now().isoformat()
        result.phases.append(HuntPhaseResult(
            phase="dry_run",
            success=True,
            message="Dry run complete — no tests were deployed.",
        ))
        return result
    
    # ========================================================================
    # Phase 3: Harvest Parameters
    # ========================================================================
    _notify("harvest", f"Scanning {len(all_urls)} URLs for sink parameters...")
    phase_start = time.time()
    
    all_candidates = []
    
    # Scan each URL's content
    combined_content = "\n".join(all_urls)
    candidates = harvester.scan_content(combined_content)
    
    # Filter by confidence
    candidates = [c for c in candidates if c.confidence >= config.min_confidence]
    all_candidates.extend(candidates)
    
    # Log sinks to database
    sink_ids = []
    for candidate in all_candidates:
        risk = harvester.assess_risk(candidate)
        try:
            sink_id = db.add_sink(
                surface_name=config.program_handle,
                param_name=candidate.param_name,
                method="GET",
                risk_level=risk,
                notes=f"Auto-harvested. Context: {candidate.context.value}, Confidence: {candidate.confidence:.0%}",
            )
            sink_ids.append(sink_id)
        except Exception:
            # Duplicate sink
            pass
    
    result.sinks_found = len(sink_ids)
    result.phases.append(HuntPhaseResult(
        phase="harvest",
        success=True,
        message=f"Found {len(all_candidates)} potential sinks, logged {len(sink_ids)} new",
        data={"candidates": len(all_candidates), "new_sinks": len(sink_ids)},
        duration_seconds=time.time() - phase_start,
    ))
    
    if not sink_ids:
        _notify("harvest", "No new sinks found. Hunt complete.")
        result.completed_at = datetime.now().isoformat()
        return result
    
    # ========================================================================
    # Phase 4: Deploy Canary URLs
    # ========================================================================
    _notify("deploy", "Starting interactsh session & deploying canary URLs...")
    phase_start = time.time()
    
    try:
        session = interactsh.start_session(poll_interval=config.poll_interval)
        _notify("deploy", f"Interactsh session: {session.base_url}")
        
        test_ids = []
        for sink_id in sink_ids:
            canary_url = session.generate_payload(sink_id)
            
            try:
                test_id = db.add_test(
                    sink_id=sink_id,
                    canary_uuid=canary_url.split("//")[1],  # Strip https://
                    payload_type="Direct",
                    target_url=canary_url,
                    notes="Auto-deployed by hunter",
                )
                test_ids.append(test_id)
            except Exception:
                pass
        
        result.tests_deployed = len(test_ids)
        result.phases.append(HuntPhaseResult(
            phase="deploy",
            success=True,
            message=f"Deployed {len(test_ids)} canary URLs",
            data={"session_url": session.base_url},
            duration_seconds=time.time() - phase_start,
        ))
    
    except Exception as e:
        result.phases.append(HuntPhaseResult(
            phase="deploy",
            success=False,
            message=f"Error starting interactsh: {e}",
            duration_seconds=time.time() - phase_start,
        ))
        result.completed_at = datetime.now().isoformat()
        return result
    
    # ========================================================================
    # Phase 5: Monitor for Callbacks
    # ========================================================================
    _notify("monitor", f"Monitoring for callbacks ({config.monitor_duration}s)...")
    phase_start = time.time()
    
    hits = []
    monitor_end = time.time() + config.monitor_duration
    
    while time.time() < monitor_end:
        interactions = interactsh.poll_interactions(session)
        
        for interaction in interactions:
            sink_id = interactsh.extract_sink_id(interaction)
            _notify(
                "monitor",
                f"🎯 HIT! Protocol: {interaction.protocol}, "
                f"From: {interaction.remote_address}"
            )
            
            hits.append({
                "protocol": interaction.protocol,
                "remote_address": interaction.remote_address,
                "timestamp": interaction.timestamp,
                "sink_id": sink_id,
            })
            
            # Update test status in DB
            if sink_id:
                tests = db.get_tests_for_sink(sink_id)
                for test in tests:
                    if test["status"] == "PENDING":
                        db.update_test_status(
                            test["id"],
                            "HIT",
                            notes=f"Auto-confirmed: {interaction.protocol} from {interaction.remote_address}",
                        )
        
        remaining = int(monitor_end - time.time())
        if remaining > 0 and remaining % 30 == 0:
            _notify("monitor", f"Monitoring... {remaining}s remaining, {len(hits)} hits so far")
        
        time.sleep(config.poll_interval)
    
    # Stop session
    final_interactions = interactsh.stop_session(session)
    for interaction in final_interactions:
        hits.append({
            "protocol": interaction.protocol,
            "remote_address": interaction.remote_address,
            "timestamp": interaction.timestamp,
        })
    
    result.hits_confirmed = len(hits)
    result.phases.append(HuntPhaseResult(
        phase="monitor",
        success=True,
        message=f"Monitoring complete. {len(hits)} callbacks received.",
        data={"hits": hits},
        duration_seconds=time.time() - phase_start,
    ))
    
    # ========================================================================
    # Complete
    # ========================================================================
    result.completed_at = datetime.now().isoformat()
    
    if config.output_dir:
        result.save(config.output_dir)
    
    return result
