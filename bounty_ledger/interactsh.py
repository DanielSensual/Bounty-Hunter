"""
interactsh.py - Interactsh callback server integration for BountyLedger.

Wraps the interactsh-client CLI to:
- Start a session and get a unique interaction URL
- Generate per-sink canary payloads
- Poll for incoming interactions (DNS, HTTP, SMTP, etc.)
- Auto-log confirmed hits to the database
"""

import subprocess
import threading
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pathlib import Path


@dataclass
class Interaction:
    """A received callback interaction."""
    unique_id: str
    full_id: str
    protocol: str  # dns, http, smtp, ldap, etc.
    raw_request: str
    remote_address: str
    timestamp: str


@dataclass 
class InteractshSession:
    """An active interactsh session with payload generation."""
    base_url: str
    process: Optional[subprocess.Popen] = None
    interactions: list[Interaction] = field(default_factory=list)
    _stop_event: threading.Event = field(default_factory=threading.Event)
    _poll_thread: Optional[threading.Thread] = None
    _output_lines: list[str] = field(default_factory=list)
    
    def generate_payload(self, sink_id: int, label: str = "") -> str:
        """
        Generate a unique canary URL for a specific sink.
        
        The label is embedded as a subdomain prefix for easy identification:
            {sink_id}-{short_uuid}.{base_url}
        
        Returns the full canary URL.
        """
        short_id = uuid.uuid4().hex[:8]
        tag = f"s{sink_id}"
        if label:
            # Sanitize label for DNS compatibility
            safe_label = re.sub(r'[^a-z0-9-]', '', label.lower())[:20]
            tag = f"{tag}-{safe_label}"
        
        canary_host = f"{tag}-{short_id}.{self.base_url}"
        return f"https://{canary_host}"
    
    def is_running(self) -> bool:
        """Check if the session is still active."""
        return self.process is not None and self.process.poll() is None


def _find_interactsh_binary() -> str:
    """Find the interactsh-client binary."""
    import shutil
    
    # Check common locations
    candidates = [
        "interactsh-client",
        str(Path.home() / "go" / "bin" / "interactsh-client"),
    ]
    
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    
    # Direct check without which
    go_bin = Path.home() / "go" / "bin" / "interactsh-client"
    if go_bin.exists():
        return str(go_bin)
    
    raise FileNotFoundError(
        "interactsh-client not found. Run 'bash setup.sh' to install it."
    )


def start_session(
    server: str = "",
    token: str = "",
    poll_interval: int = 5,
) -> InteractshSession:
    """
    Start a new interactsh session.
    
    Launches interactsh-client as a subprocess, captures the generated
    interaction URL, and starts a background thread to collect interactions.
    
    Args:
        server: Custom interactsh server URL (default: ProjectDiscovery's public server)
        token: Authentication token for the server
        poll_interval: How often to check for new interactions (seconds)
    
    Returns:
        InteractshSession with the generated base URL
    """
    binary = _find_interactsh_binary()
    
    cmd = [binary, "-json", "-poll-interval", str(poll_interval)]
    
    if server:
        cmd.extend(["-server", server])
    if token:
        cmd.extend(["-token", token])
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    
    # Wait for the interaction URL to appear in output
    base_url = None
    timeout = 30
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        line = process.stderr.readline()
        if not line:
            if process.poll() is not None:
                stdout_remaining = process.stdout.read() if process.stdout else ""
                stderr_remaining = process.stderr.read() if process.stderr else ""
                raise RuntimeError(
                    f"interactsh-client exited unexpectedly.\n"
                    f"stdout: {stdout_remaining}\n"
                    f"stderr: {stderr_remaining}"
                )
            continue
        
        # interactsh-client prints the URL to stderr
        # Format: [INF] Listing 1 payload for OOB Testing
        # [INF] <unique>.oast.pro
        url_match = re.search(r'([a-z0-9]+\.oast\.\w+)', line)
        if not url_match:
            url_match = re.search(r'([a-z0-9]+\.[a-z0-9]+\.interactsh\.\w+)', line)
        if not url_match:
            # Generic: any subdomain-like hostname in the line
            url_match = re.search(r'([a-z0-9]{10,}\.[a-z0-9.-]+\.\w{2,})', line)
        
        if url_match:
            base_url = url_match.group(1)
            break
    
    if not base_url:
        process.kill()
        raise TimeoutError(
            "Timed out waiting for interactsh-client to generate interaction URL. "
            "Check your network connection."
        )
    
    session = InteractshSession(
        base_url=base_url,
        process=process,
    )
    
    # Start background thread to read interactions from stdout (JSON lines)
    def _reader():
        while not session._stop_event.is_set():
            if process.stdout is None:
                break
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue
            
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                interaction = Interaction(
                    unique_id=data.get("unique-id", ""),
                    full_id=data.get("full-id", ""),
                    protocol=data.get("protocol", "unknown"),
                    raw_request=data.get("raw-request", ""),
                    remote_address=data.get("remote-address", ""),
                    timestamp=data.get("timestamp", datetime.now().isoformat()),
                )
                session.interactions.append(interaction)
            except json.JSONDecodeError:
                session._output_lines.append(line)
    
    session._poll_thread = threading.Thread(target=_reader, daemon=True)
    session._poll_thread.start()
    
    return session


def poll_interactions(session: InteractshSession) -> list[Interaction]:
    """
    Get all new interactions since the last poll.
    
    Returns a copy of the interactions list then clears it.
    """
    interactions = list(session.interactions)
    session.interactions.clear()
    return interactions


def extract_sink_id(interaction: Interaction) -> Optional[int]:
    """
    Extract the sink ID from an interaction's unique-id.
    
    Our canary format is: s{sink_id}-{label}-{short_uuid}.{base_url}
    Example: s3-calendar-a1b2c3d4.xxxxx.oast.pro
    """
    full_id = interaction.full_id or interaction.unique_id
    # Match the s{number} prefix
    match = re.match(r's(\d+)', full_id)
    if match:
        return int(match.group(1))
    return None


def stop_session(session: InteractshSession) -> list[Interaction]:
    """
    Stop the interactsh session and return any remaining interactions.
    
    Returns:
        Any interactions received since the last poll.
    """
    session._stop_event.set()
    
    remaining = list(session.interactions)
    
    if session.process and session.process.poll() is None:
        session.process.terminate()
        try:
            session.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            session.process.kill()
    
    if session._poll_thread and session._poll_thread.is_alive():
        session._poll_thread.join(timeout=3)
    
    return remaining
