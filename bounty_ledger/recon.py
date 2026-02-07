"""
recon.py - Automated reconnaissance engine for BountyLedger.

Orchestrates external recon tools via subprocess:
- subfinder: Subdomain enumeration
- httpx: Live host probing
- katana: Web crawling & URL discovery

All results are saved to the recon_output/ directory.
"""

import subprocess
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ReconResult:
    """Complete recon results for a domain."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    @property
    def summary(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains_found": len(self.subdomains),
            "live_hosts": len(self.live_hosts),
            "crawled_urls": len(self.crawled_urls),
            "errors": len(self.errors),
        }
    
    def save(self, output_dir: Path) -> Path:
        """Save results to JSON file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{self.domain.replace('.', '_')}_recon.json"
        
        data = {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "crawled_urls": self.crawled_urls,
            "errors": self.errors,
            "summary": self.summary,
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        return output_file


# ============================================================================
# Tool Locators
# ============================================================================

def _find_tool(name: str) -> str:
    """Find a tool binary, checking Go bin path."""
    # Check PATH first
    path = shutil.which(name)
    if path:
        return path
    
    # Check Go bin
    go_bin = Path.home() / "go" / "bin" / name
    if go_bin.exists():
        return str(go_bin)
    
    raise FileNotFoundError(
        f"{name} not found. Run 'bash setup.sh' to install it."
    )


def _run_tool(cmd: list[str], timeout: int = 300) -> tuple[str, str]:
    """Run a tool and return stdout, stderr."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout, result.stderr


# ============================================================================
# Recon Functions
# ============================================================================

def enumerate_subdomains(
    domain: str,
    max_results: int = 500,
    timeout: int = 120,
    silent: bool = True,
) -> list[str]:
    """
    Find subdomains for a domain using subfinder.
    
    Args:
        domain: Target domain (e.g., 'shopify.com')
        max_results: Maximum subdomains to return
        timeout: Timeout in seconds
        silent: Suppress subfinder banner/progress
    
    Returns:
        List of discovered subdomains
    """
    binary = _find_tool("subfinder")
    
    cmd = [binary, "-d", domain, "-silent"]
    if silent:
        cmd.append("-silent")
    
    try:
        stdout, stderr = _run_tool(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return []
    
    subdomains = [
        line.strip() 
        for line in stdout.strip().split("\n") 
        if line.strip()
    ]
    
    # Deduplicate and limit
    subdomains = list(dict.fromkeys(subdomains))[:max_results]
    return subdomains


def probe_live_hosts(
    subdomains: list[str],
    timeout: int = 180,
    threads: int = 25,
    rate_limit: int = 50,
) -> list[dict]:
    """
    Probe subdomains for live HTTP/HTTPS services using httpx.
    
    Args:
        subdomains: List of subdomains to probe
        timeout: Timeout in seconds
        threads: Number of concurrent threads
        rate_limit: Requests per second
    
    Returns:
        List of dicts with host, status_code, title, tech, etc.
    """
    binary = _find_tool("httpx")
    
    # Write subdomains to temp file for stdin
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("\n".join(subdomains))
        input_file = f.name
    
    cmd = [
        binary,
        "-l", input_file,
        "-silent",
        "-json",
        "-threads", str(threads),
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-no-color",
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
    ]
    
    try:
        stdout, stderr = _run_tool(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return []
    finally:
        Path(input_file).unlink(missing_ok=True)
    
    hosts = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            hosts.append({
                "url": data.get("url", ""),
                "host": data.get("host", ""),
                "status_code": data.get("status_code", 0),
                "title": data.get("title", ""),
                "technologies": data.get("tech", []),
                "content_length": data.get("content_length", 0),
                "webserver": data.get("webserver", ""),
            })
        except json.JSONDecodeError:
            continue
    
    return hosts


def crawl_urls(
    hosts: list[str],
    depth: int = 3,
    timeout: int = 300,
    rate_limit: int = 10,
    max_urls: int = 1000,
) -> list[str]:
    """
    Crawl live hosts to discover URLs and parameters using katana.
    
    Args:
        hosts: List of host URLs to crawl
        depth: Maximum crawl depth
        timeout: Timeout in seconds
        rate_limit: Requests per second
        max_urls: Maximum URLs to collect
    
    Returns:
        List of discovered URLs with parameters
    """
    binary = _find_tool("katana")
    
    # Write hosts to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("\n".join(hosts))
        input_file = f.name
    
    cmd = [
        binary,
        "-list", input_file,
        "-silent",
        "-depth", str(depth),
        "-rate-limit", str(rate_limit),
        "-no-color",
        "-field", "url",
        "-known-files", "all",
        "-form-extraction",
    ]
    
    try:
        stdout, stderr = _run_tool(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return []
    finally:
        Path(input_file).unlink(missing_ok=True)
    
    urls = [
        line.strip()
        for line in stdout.strip().split("\n")
        if line.strip()
    ]
    
    # Deduplicate and limit
    urls = list(dict.fromkeys(urls))[:max_urls]
    return urls


def full_recon(
    domain: str,
    output_dir: Optional[Path] = None,
    max_subdomains: int = 500,
    crawl_depth: int = 3,
    rate_limit: int = 10,
) -> ReconResult:
    """
    Full automated recon pipeline: subdomains → live hosts → crawl.
    
    Args:
        domain: Target domain
        output_dir: Directory to save results (default: recon_output/)
        max_subdomains: Maximum subdomains to enumerate
        crawl_depth: Katana crawl depth
        rate_limit: Requests per second for crawling
    
    Returns:
        ReconResult with all discovered data
    """
    if output_dir is None:
        output_dir = Path(__file__).parent.parent / "recon_output"
    
    result = ReconResult(domain=domain)
    
    # Step 1: Enumerate subdomains
    try:
        result.subdomains = enumerate_subdomains(
            domain, max_results=max_subdomains
        )
    except FileNotFoundError as e:
        result.errors.append(f"subfinder: {e}")
    except Exception as e:
        result.errors.append(f"subfinder error: {e}")
    
    if not result.subdomains:
        result.subdomains = [domain]  # Fall back to base domain
    
    # Step 2: Probe for live hosts
    try:
        result.live_hosts = probe_live_hosts(result.subdomains)
    except FileNotFoundError as e:
        result.errors.append(f"httpx: {e}")
    except Exception as e:
        result.errors.append(f"httpx error: {e}")
    
    # Step 3: Crawl live hosts for URLs
    if result.live_hosts:
        host_urls = [h["url"] for h in result.live_hosts if h.get("url")]
        try:
            result.crawled_urls = crawl_urls(
                host_urls,
                depth=crawl_depth,
                rate_limit=rate_limit,
            )
        except FileNotFoundError as e:
            result.errors.append(f"katana: {e}")
        except Exception as e:
            result.errors.append(f"katana error: {e}")
    
    # Save results
    result.save(output_dir)
    
    return result
