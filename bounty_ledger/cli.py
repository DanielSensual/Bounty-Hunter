"""
cli.py - Typer CLI orchestrator for BountyLedger.

Commands:
- hunt: Autonomous bug hunting pipeline
- recon: Run recon on a domain
- scope: Show HackerOne program scope
- monitor: Start callback listener
- setup: First-time configuration wizard
- scan: Parse text/files for potential sinks
- add-sink: Log a confirmed sink
- gen-test: Generate canary URL with safety checks
- report: Generate Markdown report
- list-sinks: Show all sinks
- list-tests: Show all tests
- stats: Show summary statistics
"""

import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Annotated

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown

from . import database as db
from . import guardrails
from . import harvester

# ============================================================================
# App Setup
# ============================================================================

app = typer.Typer(
    name="bounty",
    help="🎯 BountyLedger - Agentic Bug Bounty Hunting Pipeline",
    add_completion=False,
    rich_markup_mode="rich"
)

console = Console()

# Config file path
CONFIG_PATH = Path(__file__).parent.parent / "config.json"


def load_config() -> dict:
    """Load configuration from config.json."""
    if not CONFIG_PATH.exists():
        return {
            "listener_domain": "your-collaborator.com",
            "allowed_scope": []
        }
    
    with open(CONFIG_PATH) as f:
        return json.load(f)


def ensure_db():
    """Ensure database is initialized."""
    db.init_db()


# ============================================================================
# SCAN Command
# ============================================================================

@app.command()
def scan(
    content: Annotated[str, typer.Argument(help="Text to scan, or path to a file (.txt, .har)")],
    min_confidence: Annotated[float, typer.Option("--min-conf", "-c", help="Minimum confidence threshold")] = 0.3,
):
    """
    🔍 Scan text or files for potential sink parameters.
    
    Accepts raw text (e.g., HTTP request) or a file path (.txt, .har).
    """
    # Check if content is a file path
    path = Path(content)
    if path.exists() and path.is_file():
        console.print(f"[dim]Scanning file: {path}[/dim]")
        candidates = harvester.scan_file(path)
    else:
        candidates = harvester.scan_content(content)
    
    # Filter by confidence
    candidates = [c for c in candidates if c.confidence >= min_confidence]
    
    if not candidates:
        console.print("[yellow]No potential sink parameters found.[/yellow]")
        return
    
    # Build table
    table = Table(title="🎯 Potential Sink Parameters", show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("Parameter", style="cyan")
    table.add_column("Context", style="green")
    table.add_column("Risk", style="red")
    table.add_column("Conf", justify="right")
    table.add_column("Sample Value", style="dim", max_width=40, overflow="ellipsis")
    
    for i, c in enumerate(candidates, 1):
        risk = harvester.assess_risk(c)
        risk_color = {"Critical": "red", "High": "yellow", "Medium": "blue", "Low": "green"}[risk]
        
        table.add_row(
            str(i),
            c.param_name,
            c.context.value,
            f"[{risk_color}]{risk}[/{risk_color}]",
            f"{c.confidence:.0%}",
            c.sample_value or "-"
        )
    
    console.print(table)
    console.print(f"\n[dim]Use [cyan]bounty add-sink[/cyan] to log confirmed sinks.[/dim]")


# ============================================================================
# ADD-SINK Command
# ============================================================================

@app.command("add-sink")
def add_sink(
    surface: Annotated[Optional[str], typer.Option("--surface", "-s", help="Surface name (e.g., 'Calendar Import')")] = None,
    param: Annotated[Optional[str], typer.Option("--param", "-p", help="Parameter name (e.g., 'feed_url')")] = None,
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    risk: Annotated[str, typer.Option("--risk", "-r", help="Risk level: Low/Medium/High/Critical")] = "Medium",
    notes: Annotated[Optional[str], typer.Option("--notes", "-n", help="Additional notes")] = None,
):
    """
    ➕ Add a confirmed sink to the ledger.
    
    Interactive mode if no arguments provided.
    """
    ensure_db()
    
    # Interactive prompts for missing values
    if not surface:
        surface = Prompt.ask("[cyan]Surface name[/cyan] (e.g., 'Profile Settings')")
    
    if not param:
        param = Prompt.ask("[cyan]Parameter name[/cyan] (e.g., 'avatar_url')")
    
    if not surface or not param:
        console.print("[red]Error: Surface and parameter names are required.[/red]")
        raise typer.Exit(1)
    
    # Validate risk level
    valid_risks = ["Low", "Medium", "High", "Critical"]
    risk = risk.title()
    if risk not in valid_risks:
        console.print(f"[yellow]Invalid risk level. Using 'Medium'.[/yellow]")
        risk = "Medium"
    
    try:
        sink_id = db.add_sink(
            surface_name=surface,
            param_name=param,
            method=method.upper(),
            risk_level=risk,
            notes=notes
        )
        
        console.print(Panel(
            f"[green]✓ Sink added successfully![/green]\n\n"
            f"[dim]ID:[/dim] [cyan]{sink_id}[/cyan]\n"
            f"[dim]Surface:[/dim] {surface}\n"
            f"[dim]Parameter:[/dim] {param}\n"
            f"[dim]Method:[/dim] {method.upper()}\n"
            f"[dim]Risk:[/dim] {risk}",
            title="Sink Logged"
        ))
        
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            console.print("[yellow]⚠ This sink already exists in the database.[/yellow]")
        else:
            console.print(f"[red]Error adding sink: {e}[/red]")
            raise typer.Exit(1)


# ============================================================================
# GEN-TEST Command
# ============================================================================

@app.command("gen-test")
def gen_test(
    sink_id: Annotated[int, typer.Argument(help="ID of the sink to test")],
    payload_type: Annotated[str, typer.Option("--type", "-t", help="Payload type: Direct, Redirect-302, Redirect-307, DNS-Rebind")] = "Direct",
    target_url: Annotated[Optional[str], typer.Option("--target", help="Target URL for redirect payloads")] = None,
    notes: Annotated[Optional[str], typer.Option("--notes", "-n", help="Test notes")] = None,
):
    """
    🧪 Generate a test canary URL for a sink.
    
    Creates a unique UUID and logs the test as PENDING.
    """
    ensure_db()
    config = load_config()
    
    # Get sink details
    sink = db.get_sink(sink_id)
    if not sink:
        console.print(f"[red]Error: Sink with ID {sink_id} not found.[/red]")
        raise typer.Exit(1)
    
    # Validate payload type
    valid_types = ["Direct", "Redirect-302", "Redirect-307", "DNS-Rebind"]
    payload_type = payload_type.title().replace("redirect", "Redirect")
    if payload_type not in valid_types:
        console.print(f"[yellow]Invalid payload type. Using 'Direct'.[/yellow]")
        payload_type = "Direct"
    
    # For redirect types, validate target URL
    if payload_type.startswith("Redirect") and target_url:
        result = guardrails.is_safe_target(target_url)
        if not result:
            console.print(Panel(
                f"[red]⛔ BLOCKED by safety guardrails![/red]\n\n"
                f"[dim]Reason:[/dim] {result.reason}\n\n"
                f"[dim]This tool does not allow targeting private/internal addresses.[/dim]",
                title="Safety Check Failed",
                border_style="red"
            ))
            raise typer.Exit(1)
        
        # Also check scope
        if config.get("allowed_scope"):
            scope_result = guardrails.check_scope(target_url, config["allowed_scope"])
            if not scope_result:
                console.print(f"[yellow]⚠ Warning: Target URL not in allowed scope.[/yellow]")
                console.print(f"[dim]Scope: {config['allowed_scope']}[/dim]")
                if not Confirm.ask("Continue anyway?"):
                    raise typer.Exit(0)
    
    # Generate unique canary UUID
    canary_uuid = str(uuid.uuid4())
    
    # Create surface slug from surface name
    surface_slug = re.sub(r'[^a-z0-9]+', '-', sink['surface_name'].lower()).strip('-')
    
    # Build canary URL
    listener_domain = config.get("listener_domain", "your-collaborator.com")
    canary_url = f"https://{listener_domain}/{surface_slug}/{canary_uuid}"
    
    # Log the test
    test_id = db.add_test(
        sink_id=sink_id,
        canary_uuid=canary_uuid,
        payload_type=payload_type,
        target_url=target_url,
        notes=notes
    )
    
    # Display result
    console.print(Panel(
        f"[green]✓ Test generated successfully![/green]\n\n"
        f"[dim]Test ID:[/dim] [cyan]{test_id}[/cyan]\n"
        f"[dim]Sink:[/dim] {sink['surface_name']} → {sink['param_name']}\n"
        f"[dim]Payload Type:[/dim] {payload_type}\n"
        f"[dim]Status:[/dim] [yellow]PENDING[/yellow]\n\n"
        f"[bold]📋 Safe Canary URL (copy this):[/bold]\n"
        f"[cyan]{canary_url}[/cyan]",
        title="🧪 Test Generated"
    ))
    
    if payload_type.startswith("Redirect") and target_url:
        console.print(f"\n[dim]Redirect target: {target_url}[/dim]")
    
    console.print(f"\n[dim]Use [cyan]bounty mark-hit {test_id}[/cyan] when you receive a callback.[/dim]")


# ============================================================================
# MARK-HIT Command
# ============================================================================

@app.command("mark-hit")
def mark_hit(
    test_id: Annotated[int, typer.Argument(help="ID of the test that received a hit")],
    notes: Annotated[Optional[str], typer.Option("--notes", "-n", help="Notes about the hit")] = None,
):
    """
    🎯 Mark a test as HIT (callback received).
    """
    ensure_db()
    
    test = db.get_test(test_id)
    if not test:
        console.print(f"[red]Error: Test with ID {test_id} not found.[/red]")
        raise typer.Exit(1)
    
    if db.update_test_status(test_id, "HIT", notes):
        console.print(Panel(
            f"[green]🎉 HIT recorded![/green]\n\n"
            f"[dim]Test ID:[/dim] {test_id}\n"
            f"[dim]Sink:[/dim] {test['surface_name']} → {test['param_name']}\n"
            f"[dim]Timestamp:[/dim] {datetime.now().isoformat()}",
            title="Callback Confirmed",
            border_style="green"
        ))
    else:
        console.print("[red]Failed to update test status.[/red]")


# ============================================================================
# REPORT Command
# ============================================================================

@app.command("report")
def report(
    test_id: Annotated[int, typer.Argument(help="ID of the test to report")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save to file")] = None,
):
    """
    📄 Generate a professional Markdown report for a test.
    """
    ensure_db()
    
    test = db.get_test(test_id)
    if not test:
        console.print(f"[red]Error: Test with ID {test_id} not found.[/red]")
        raise typer.Exit(1)
    
    # Build Markdown report
    status_emoji = {"PENDING": "⏳", "HIT": "🎯", "CLOSED": "✅"}.get(test['status'], "❓")
    
    md_content = f"""## Vulnerability Report: Server-Side Request Forgery (SSRF)

### Summary
| Field | Value |
|-------|-------|
| **Surface** | {test['surface_name']} |
| **Parameter** | `{test['param_name']}` |
| **Method** | `{test['method']}` |
| **Risk Level** | {test['risk_level']} |
| **Payload Type** | {test['payload_type']} |
| **Status** | {status_emoji} {test['status']} |
| **Test ID** | {test['id']} |
| **Canary UUID** | `{test['canary_uuid']}` |
| **Timestamp** | {test['timestamp']} |

### Technical Details

**Affected Endpoint**: [Add endpoint URL here]

**Vulnerable Parameter**: `{test['param_name']}`

**Payload Used**: 
```
{test['payload_type']} request to canary UUID: {test['canary_uuid']}
```

### Impact

[Describe the potential impact of this vulnerability]

- [ ] Internal service enumeration
- [ ] Cloud metadata access (169.254.169.254)
- [ ] Internal network scanning
- [ ] Data exfiltration

### Steps to Reproduce

1. Navigate to [{test['surface_name']}]
2. Locate the `{test['param_name']}` parameter
3. Submit the canary URL
4. Observe callback on external listener

### Remediation

- Implement URL allowlist validation
- Block internal/private IP ranges
- Use a URL parser to validate schemes (http/https only)
- Consider using a proxy/gateway for outbound requests

---
*Generated by BountyLedger - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
    
    if output:
        output.write_text(md_content)
        console.print(f"[green]✓ Report saved to: {output}[/green]")
    else:
        console.print(Panel(Markdown(md_content), title="📄 Vulnerability Report"))
    
    console.print(f"\n[dim]Copy the Markdown above to include in your bug bounty submission.[/dim]")


# ============================================================================
# LIST Commands
# ============================================================================

@app.command("list-sinks")
def list_sinks():
    """📋 List all tracked sinks."""
    ensure_db()
    
    sinks = db.get_all_sinks()
    
    if not sinks:
        console.print("[yellow]No sinks tracked yet. Use [cyan]bounty add-sink[/cyan] to add one.[/yellow]")
        return
    
    table = Table(title="📋 Tracked Sinks", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=4)
    table.add_column("Surface", style="cyan")
    table.add_column("Parameter", style="green")
    table.add_column("Method", width=6)
    table.add_column("Risk", width=8)
    table.add_column("Tests", justify="right", width=5)
    table.add_column("Created", style="dim")
    
    for sink in sinks:
        tests = db.get_tests_for_sink(sink['id'])
        risk_color = {"Critical": "red", "High": "yellow", "Medium": "blue", "Low": "green"}[sink['risk_level']]
        
        table.add_row(
            str(sink['id']),
            sink['surface_name'],
            sink['param_name'],
            sink['method'],
            f"[{risk_color}]{sink['risk_level']}[/{risk_color}]",
            str(len(tests)),
            sink['created_at'][:10]
        )
    
    console.print(table)


@app.command("list-tests")
def list_tests(
    status: Annotated[Optional[str], typer.Option("--status", "-s", help="Filter by status: PENDING, HIT, CLOSED")] = None,
):
    """📋 List all tests."""
    ensure_db()
    
    tests = db.get_all_tests()
    
    if status:
        tests = [t for t in tests if t['status'] == status.upper()]
    
    if not tests:
        console.print("[yellow]No tests found.[/yellow]")
        return
    
    table = Table(title="📋 Tests", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=4)
    table.add_column("Sink", style="cyan")
    table.add_column("Param", style="green")
    table.add_column("Type", width=12)
    table.add_column("Status", width=8)
    table.add_column("UUID", style="dim", max_width=20, overflow="ellipsis")
    table.add_column("Timestamp", style="dim", width=12)
    
    for test in tests:
        status_color = {"PENDING": "yellow", "HIT": "green", "CLOSED": "dim"}[test['status']]
        
        table.add_row(
            str(test['id']),
            test['surface_name'],
            test['param_name'],
            test['payload_type'],
            f"[{status_color}]{test['status']}[/{status_color}]",
            test['canary_uuid'][:8] + "...",
            test['timestamp'][:10]
        )
    
    console.print(table)


# ============================================================================
# STATS Command
# ============================================================================

@app.command("stats")
def stats():
    """📊 Show summary statistics."""
    ensure_db()
    
    s = db.get_stats()
    
    console.print(Panel(
        f"[bold]📊 BountyLedger Statistics[/bold]\n\n"
        f"[dim]Total Sinks:[/dim]    [cyan]{s['total_sinks']}[/cyan]\n"
        f"[dim]Total Tests:[/dim]    [cyan]{s['total_tests']}[/cyan]\n\n"
        f"[dim]Pending:[/dim]        [yellow]{s['pending_tests']}[/yellow]\n"
        f"[dim]Hits:[/dim]           [green]{s['hit_tests']}[/green]\n"
        f"[dim]Closed:[/dim]         [dim]{s['closed_tests']}[/dim]",
        title="Statistics"
    ))


# ============================================================================
# CONFIG Command
# ============================================================================

@app.command("config")
def show_config():
    """⚙️ Show current configuration."""
    config = load_config()
    
    console.print(Panel(
        f"[dim]Listener Domain:[/dim]  [cyan]{config.get('listener_domain', 'Not set')}[/cyan]\n"
        f"[dim]Allowed Scope:[/dim]    {config.get('allowed_scope', [])}",
        title="⚙️ Configuration"
    ))
    console.print(f"\n[dim]Edit [cyan]{CONFIG_PATH}[/cyan] to change settings.[/dim]")


# ============================================================================
# GEN-REDIRECT-SCRIPT Command
# ============================================================================

@app.command("gen-redirect-script")
def gen_redirect_script(
    target: Annotated[str, typer.Argument(help="Target URL/IP for the redirect (e.g., 127.0.0.1:80)")],
    port: Annotated[int, typer.Option("--port", "-p", help="Port to run the redirect server")] = 8080,
    language: Annotated[str, typer.Option("--lang", "-l", help="Language: python or php")] = "python",
):
    """
    🔄 Generate a redirect script for bypass testing.
    
    Creates a small script to host on your server that performs 302 redirects.
    
    ⚠️ This is for authorized testing only!
    """
    
    if language.lower() == "python":
        script = f'''#!/usr/bin/env python3
"""
302 Redirect Server for SSRF Bypass Testing
Target: {target}
Port: {port}

Run: python3 redirect_server.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler

TARGET = "{target}"

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Construct target URL
        target_url = TARGET if TARGET.startswith(('http://', 'https://')) else f"http://{{TARGET}}"
        target_url = target_url + self.path if self.path != '/' else target_url
        
        self.send_response(302)
        self.send_header('Location', target_url)
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        
        print(f"[*] Redirected to: {{target_url}}")
    
    do_POST = do_GET
    do_PUT = do_GET

if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', {port}), RedirectHandler)
    print(f"[*] Redirect server running on port {port}")
    print(f"[*] Redirecting all requests to: {{TARGET}}")
    server.serve_forever()
'''
    else:  # PHP
        script = f'''<?php
/**
 * 302 Redirect Script for SSRF Bypass Testing
 * Target: {target}
 * 
 * Deploy to your PHP-enabled web server.
 */

$target = "{target}";

// Construct full target URL
if (!preg_match('/^https?:\\/\\//', $target)) {{
    $target = "http://" . $target;
}}

// Append request path if present
if (isset($_SERVER['PATH_INFO']) && $_SERVER['PATH_INFO'] !== '/') {{
    $target .= $_SERVER['PATH_INFO'];
}}

// Perform 302 redirect
header("HTTP/1.1 302 Found");
header("Location: " . $target);
header("Cache-Control: no-cache");

error_log("[*] Redirected to: " . $target);
exit;
?>
'''
    
    console.print(Panel(
        f"[bold]🔄 Redirect Script Generated[/bold]\n\n"
        f"[dim]Target:[/dim] {target}\n"
        f"[dim]Language:[/dim] {language.upper()}\n"
        f"[dim]Port:[/dim] {port}",
        title="Redirect Server"
    ))
    
    console.print(f"\n```{language}")
    console.print(script)
    console.print("```")
    
    console.print(f"\n[yellow]⚠️ Use responsibly! Only for authorized testing.[/yellow]")


# ============================================================================
# META-TEST Command (Meta Bug Bounty Integration)
# ============================================================================

@app.command("meta-test")
def meta_test(
    sink_id: Annotated[int, typer.Argument(help="ID of the sink to test")],
    canary_url: Annotated[str, typer.Argument(help="Meta canary URL from internalfb.com SSRF tool")],
    payload_type: Annotated[str, typer.Option("--type", "-t", help="Payload type")] = "Direct",
    notes: Annotated[Optional[str], typer.Option("--notes", "-n", help="Additional notes")] = None,
):
    """
    🔵 Log a test using Meta's official SSRF canary URL.
    
    Use this after generating a canary at:
    https://www.internalfb.com/intern/bug-bounty/get-canary-token/
    
    Example:
        bounty meta-test 1 "https://www.internalfb.com/intern/bug-bounty/get-canary-token/abc123..."
    """
    ensure_db()
    
    # Get sink details
    sink = db.get_sink(sink_id)
    if not sink:
        console.print(f"[red]Error: Sink with ID {sink_id} not found.[/red]")
        raise typer.Exit(1)
    
    # Validate Meta canary URL format
    if "internalfb.com" not in canary_url and "facebook.com" not in canary_url:
        console.print("[yellow]⚠ Warning: This doesn't look like a Meta canary URL.[/yellow]")
        if not Confirm.ask("Continue anyway?"):
            raise typer.Exit(0)
    
    # Extract token ID from URL
    token_match = re.search(r'get-canary-token/([a-f0-9]+)', canary_url)
    if token_match:
        canary_uuid = f"meta:{token_match.group(1)}"
    else:
        # Use a hash of the URL as UUID
        canary_uuid = f"meta:{uuid.uuid5(uuid.NAMESPACE_URL, canary_url).hex[:32]}"
    
    # Log the test
    test_id = db.add_test(
        sink_id=sink_id,
        canary_uuid=canary_uuid,
        payload_type=payload_type,
        target_url=canary_url,  # Store full Meta URL
        notes=notes or f"Meta canary: {canary_url}"
    )
    
    console.print(Panel(
        f"[blue]🔵 Meta SSRF Test Logged[/blue]\n\n"
        f"[dim]Test ID:[/dim] [cyan]{test_id}[/cyan]\n"
        f"[dim]Sink:[/dim] {sink['surface_name']} → {sink['param_name']}\n"
        f"[dim]Payload Type:[/dim] {payload_type}\n"
        f"[dim]Status:[/dim] [yellow]PENDING[/yellow]\n\n"
        f"[bold]📋 Meta Canary URL:[/bold]\n"
        f"[cyan]{canary_url}[/cyan]",
        title="🔵 Meta Bug Bounty Test"
    ))
    
    console.print(f"\n[dim]Submit this URL to the vulnerable parameter.[/dim]")
    console.print(f"[dim]Check Meta's SSRF portal for hit count, then run:[/dim]")
    console.print(f"[cyan]bounty mark-hit {test_id} --notes \"Hit count: X\"[/cyan]")


@app.command("meta-check")
def meta_check(
    test_id: Annotated[Optional[int], typer.Argument(help="Test ID to check (optional)")] = None,
):
    """
    🔵 Show Meta canary tests and their portal URLs.
    
    Displays all tests using Meta canary URLs so you can check hit counts.
    """
    ensure_db()
    
    tests = db.get_all_tests()
    meta_tests = [t for t in tests if t.get('canary_uuid', '').startswith('meta:')]
    
    if test_id:
        meta_tests = [t for t in meta_tests if t['id'] == test_id]
    
    if not meta_tests:
        console.print("[yellow]No Meta canary tests found.[/yellow]")
        console.print("[dim]Use [cyan]bounty meta-test[/cyan] to log one.[/dim]")
        return
    
    table = Table(title="🔵 Meta SSRF Canary Tests", show_header=True, header_style="bold blue")
    table.add_column("ID", style="dim", width=4)
    table.add_column("Sink", style="cyan")
    table.add_column("Status", width=8)
    table.add_column("Canary URL", style="dim", max_width=60, overflow="ellipsis")
    
    for test in meta_tests:
        status_color = {"PENDING": "yellow", "HIT": "green", "CLOSED": "dim"}[test['status']]
        
        table.add_row(
            str(test['id']),
            f"{test['surface_name']} → {test['param_name']}",
            f"[{status_color}]{test['status']}[/{status_color}]",
            test.get('target_url', '-')
        )
    
    console.print(table)
    console.print(f"\n[dim]Check hit counts at: [cyan]https://www.internalfb.com/intern/bug-bounty/[/cyan][/dim]")


# ============================================================================
# HUNT Command (Agentic Pipeline)
# ============================================================================

@app.command("hunt")
def hunt_cmd(
    program: Annotated[str, typer.Argument(help="HackerOne program handle (e.g., 'shopify')")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Simulate hunt without sending requests")] = False,
    max_subs: Annotated[int, typer.Option("--max-subs", help="Max subdomains to enumerate")] = 500,
    crawl_depth: Annotated[int, typer.Option("--depth", help="Crawl depth")] = 3,
    rate_limit: Annotated[int, typer.Option("--rate", help="Requests per second")] = 10,
    monitor_time: Annotated[int, typer.Option("--monitor", "-m", help="Callback monitor duration (seconds)")] = 300,
):
    """
    🚀 Launch autonomous bug hunt against a program.
    
    Runs the full pipeline: scope → recon → harvest → test → monitor.
    """
    from . import hunter
    
    ensure_db()
    
    config = hunter.HuntConfig(
        program_handle=program,
        max_subdomains=max_subs,
        crawl_depth=crawl_depth,
        rate_limit=rate_limit,
        monitor_duration=monitor_time,
        dry_run=dry_run,
    )
    
    console.print(Panel(
        f"[bold]🚀 Launching Hunt: {program}[/bold]\n\n"
        f"[dim]Dry Run:[/dim]    {'Yes' if dry_run else 'No'}\n"
        f"[dim]Max Subs:[/dim]   {max_subs}\n"
        f"[dim]Crawl Depth:[/dim]{crawl_depth}\n"
        f"[dim]Rate Limit:[/dim] {rate_limit} req/s\n"
        f"[dim]Monitor:[/dim]    {monitor_time}s",
        title="🎯 BountyLedger Hunt",
        border_style="cyan"
    ))
    
    if not dry_run and not Confirm.ask("\n[yellow]Start the hunt?[/yellow]"):
        raise typer.Exit(0)
    
    def on_phase(phase: str, message: str):
        phase_icons = {
            "scope": "🔍", "recon": "🌐", "harvest": "🎣",
            "deploy": "🚀", "monitor": "📡", "dry_run": "🧪"
        }
        icon = phase_icons.get(phase, "⚡")
        console.print(f"  {icon} [dim]{phase}:[/dim] {message}")
    
    console.print("\n")
    result = hunter.hunt(config, on_phase=on_phase)
    
    # Summary
    status_color = "green" if result.success else "red"
    console.print(f"\n")
    console.print(Panel(
        f"[{status_color}]{'✓ Hunt Complete' if result.success else '✗ Hunt had errors'}[/{status_color}]\n\n"
        f"[dim]Domains Scanned:[/dim]  [cyan]{result.domains_scanned}[/cyan]\n"
        f"[dim]Sinks Found:[/dim]      [cyan]{result.sinks_found}[/cyan]\n"
        f"[dim]Tests Deployed:[/dim]   [cyan]{result.tests_deployed}[/cyan]\n"
        f"[dim]Hits Confirmed:[/dim]   [green]{result.hits_confirmed}[/green]\n\n"
        f"[dim]Duration:[/dim]          {result.started_at[:19]} → {result.completed_at[:19]}",
        title="📊 Hunt Results",
        border_style=status_color
    ))
    
    if result.hits_confirmed > 0:
        console.print(f"\n[green bold]🎉 {result.hits_confirmed} confirmed hit(s)! Run 'bounty list-tests --status HIT' to see them.[/green bold]")
        console.print(f"[dim]Generate a report with: bounty report <test_id>[/dim]")


# ============================================================================
# RECON Command
# ============================================================================

@app.command("recon")
def recon_cmd(
    domain: Annotated[str, typer.Argument(help="Domain to scan (e.g., 'shopify.com')")],
    max_subs: Annotated[int, typer.Option("--max-subs", help="Max subdomains")] = 500,
    crawl_depth: Annotated[int, typer.Option("--depth", help="Crawl depth")] = 3,
    rate_limit: Annotated[int, typer.Option("--rate", help="Requests per second")] = 10,
):
    """
    🌐 Run reconnaissance on a domain.
    
    Enumerates subdomains, probes live hosts, and crawls for URLs.
    """
    from . import recon
    
    console.print(f"[cyan]🌐 Starting recon on: {domain}[/cyan]\n")
    
    with console.status("[bold green]Enumerating subdomains...") as status:
        try:
            status.update("[bold green]Finding subdomains...")
            subdomains = recon.enumerate_subdomains(domain, max_results=max_subs)
            console.print(f"  [green]✓[/green] Found {len(subdomains)} subdomains")
            
            status.update("[bold green]Probing live hosts...")
            hosts = recon.probe_live_hosts(subdomains)
            console.print(f"  [green]✓[/green] {len(hosts)} live hosts responding")
            
            if hosts:
                status.update("[bold green]Crawling URLs...")
                host_urls = [h['url'] for h in hosts if h.get('url')]
                urls = recon.crawl_urls(
                    host_urls, depth=crawl_depth, rate_limit=rate_limit
                )
                console.print(f"  [green]✓[/green] Discovered {len(urls)} URLs")
            else:
                urls = []
        
        except FileNotFoundError as e:
            console.print(f"[red]✗ {e}[/red]")
            console.print("[dim]Run 'bash setup.sh' to install required tools.[/dim]")
            raise typer.Exit(1)
    
    # Show top hosts
    if hosts:
        table = Table(title="🌐 Live Hosts", show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan", max_width=50)
        table.add_column("Status", width=6)
        table.add_column("Title", max_width=30)
        table.add_column("Tech", style="dim", max_width=30)
        
        for host in hosts[:20]:
            table.add_row(
                host['url'],
                str(host['status_code']),
                host.get('title', '-')[:30],
                ', '.join(host.get('technologies', []))[:30] or '-',
            )
        
        console.print(table)
    
    # Quick scan for sinks
    if urls:
        combined = "\n".join(urls)
        candidates = harvester.scan_content(combined)
        candidates = [c for c in candidates if c.confidence >= 0.5]
        
        if candidates:
            console.print(f"\n[yellow]🎣 Found {len(candidates)} potential sink parameters![/yellow]")
            console.print("[dim]Run 'bounty scan' on specific URLs for details.[/dim]")
    
    console.print(f"\n[dim]Results saved to recon_output/[/dim]")


# ============================================================================
# SCOPE Command
# ============================================================================

@app.command("scope")
def scope_cmd(
    program: Annotated[str, typer.Argument(help="HackerOne program handle (e.g., 'shopify')")],
):
    """
    🔍 Show in-scope assets for a HackerOne program.
    """
    from . import hackerone
    
    try:
        client = hackerone.HackerOneClient.from_config(CONFIG_PATH)
        
        if not client.is_configured:
            console.print("[red]HackerOne API not configured.[/red]")
            console.print("[dim]Run 'bounty setup' to configure your API credentials.[/dim]")
            raise typer.Exit(1)
        
        with console.status(f"[bold green]Fetching scope for {program}..."):
            program_info = client.get_program_scope(program)
        
        console.print(Panel(
            f"[bold]{program_info.name}[/bold]\n"
            f"[dim]Handle:[/dim]    {program_info.handle}\n"
            f"[dim]URL:[/dim]       [cyan]{program_info.url}[/cyan]\n"
            f"[dim]Bounties:[/dim]  {'Yes' if program_info.offers_bounties else 'No'}\n"
            f"[dim]State:[/dim]     {program_info.state}",
            title="🔍 Program Info"
        ))
        
        if program_info.scope_assets:
            table = Table(title="📋 In-Scope Assets", show_header=True, header_style="bold magenta")
            table.add_column("Type", width=10)
            table.add_column("Asset", style="cyan")
            table.add_column("Bounty", width=7)
            table.add_column("Max Severity", width=12)
            
            for asset in program_info.scope_assets:
                bounty_indicator = "[green]💰 Yes[/green]" if asset.eligible_for_bounty else "[dim]No[/dim]"
                table.add_row(
                    asset.asset_type,
                    asset.asset_identifier,
                    bounty_indicator,
                    asset.max_severity or "-",
                )
            
            console.print(table)
            
            web_domains = program_info.web_domains
            if web_domains:
                console.print(f"\n[dim]Web domains for recon: {', '.join(web_domains[:10])}[/dim]")
        else:
            console.print("[yellow]No structured scope data available.[/yellow]")
    
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# ============================================================================
# MONITOR Command
# ============================================================================

@app.command("monitor")
def monitor_cmd(
    duration: Annotated[int, typer.Option("--duration", "-d", help="Monitor duration in seconds (0 = indefinite)")] = 0,
    port: Annotated[int, typer.Option("--port", "-P", help="Callback server port")] = 8888,
    self_hosted: Annotated[bool, typer.Option("--self-hosted/--interactsh", help="Use self-hosted callback server")] = True,
):
    """
    📡 Start the callback monitor.
    
    Listens for incoming callbacks and auto-logs hits.
    Uses self-hosted callback server by default (interactsh as fallback).
    """
    ensure_db()
    
    if not self_hosted:
        # Legacy interactsh mode
        from . import interactsh as ish
        console.print("[cyan]📡 Starting callback monitor (interactsh)...[/cyan]")
        try:
            session = ish.start_session(poll_interval=5)
            console.print(f"[green]✓ Session active: {session.base_url}[/green]")
            console.print(f"[dim]Monitoring for callbacks... (Ctrl+C to stop)[/dim]\n")
            
            hit_count = 0
            try:
                while True:
                    interactions = ish.poll_interactions(session)
                    for interaction in interactions:
                        hit_count += 1
                        console.print(
                            f"  [green]🎯 HIT #{hit_count}[/green] "
                            f"Protocol: [cyan]{interaction.protocol}[/cyan] "
                            f"From: [yellow]{interaction.remote_address}[/yellow]"
                        )
                    __import__('time').sleep(5)
                    if duration > 0 and __import__('time').time() - __import__('time').time() >= duration:
                        break
            except KeyboardInterrupt:
                console.print("\n[dim]Stopping monitor...[/dim]")
            ish.stop_session(session)
            console.print(f"\n[cyan]📡 Monitor stopped. Total hits: {hit_count}[/cyan]")
        except (FileNotFoundError, Exception) as e:
            console.print(f"[red]Interactsh failed: {e}[/red]")
            console.print("[dim]Try --self-hosted mode instead.[/dim]")
            raise typer.Exit(1)
        return
    
    # Self-hosted callback server mode
    from . import callback_server as cbs
    import time as _time
    
    console.print(Panel(
        "[bold]📡 Self-Hosted Callback Server[/bold]\n\n"
        f"[dim]Port:[/dim]     [cyan]{port}[/cyan]\n"
        f"[dim]Duration:[/dim] {'Indefinite' if duration == 0 else f'{duration}s'}\n\n"
        "[yellow]⚠ Expose with ngrok for external callbacks:[/yellow]\n"
        f"  [cyan]ngrok http {port}[/cyan]",
        title="📡 Callback Monitor",
        border_style="cyan"
    ))
    
    hit_count = 0
    
    def on_hit(hit: cbs.CallbackHit):
        nonlocal hit_count
        hit_count += 1
        canary_tag = f" [green]CANARY:{hit.canary_uuid}→sink#{hit.sink_id}[/green]" if hit.canary_uuid else ""
        console.print(
            f"  [green]🎯 HIT #{hit_count}[/green] "
            f"[cyan]{hit.method}[/cyan] {hit.path} "
            f"from [yellow]{hit.remote_ip}[/yellow]{canary_tag}"
        )
        if hit.headers.get("User-Agent"):
            console.print(f"    [dim]UA: {hit.headers['User-Agent'][:80]}[/dim]")
    
    server, session = cbs.start_server(port=port, on_hit=on_hit, background=True)
    console.print(f"\n[green]✓ Listening on 0.0.0.0:{port}[/green]")
    console.print(f"[dim]Waiting for callbacks... (Ctrl+C to stop)[/dim]\n")
    
    start_time = _time.time()
    try:
        while True:
            _time.sleep(1)
            if duration > 0:
                elapsed = _time.time() - start_time
                if elapsed >= duration:
                    break
    except KeyboardInterrupt:
        console.print("\n[dim]Stopping server...[/dim]")
    
    # Save hits
    if session.hits:
        hits_path = Path(__file__).parent.parent / "recon_output" / "callback_hits.json"
        cbs.save_hits(hits_path)
        console.print(f"[green]✓ {len(session.hits)} hits saved to {hits_path}[/green]")
    
    server.shutdown()
    console.print(f"\n[cyan]📡 Monitor stopped. Total hits: {hit_count}[/cyan]")


# ============================================================================
# SETUP Command
# ============================================================================

@app.command("setup")
def setup_cmd():
    """
    ⚙️ First-time setup wizard.
    
    Configures HackerOne API credentials and target scope.
    """
    console.print(Panel(
        "[bold]⚙️ BountyLedger Setup Wizard[/bold]\n\n"
        "This will configure your bug bounty hunting environment.",
        border_style="cyan"
    ))
    
    # Load existing config
    config = load_config()
    
    # HackerOne credentials
    console.print("\n[bold cyan]Step 1: HackerOne API[/bold cyan]")
    console.print("[dim]Generate a token at: https://hackerone.com/settings/api_token/edit[/dim]\n")
    
    h1_username = Prompt.ask(
        "HackerOne username",
        default=config.get("hackerone_username", "")
    )
    h1_token = Prompt.ask(
        "HackerOne API token",
        default=config.get("hackerone_api_token", ""),
        password=True
    )
    
    if h1_username and h1_token:
        config["hackerone_username"] = h1_username
        config["hackerone_api_token"] = h1_token
        console.print("[green]✓ HackerOne credentials saved[/green]")
    else:
        console.print("[yellow]⚠ Skipped — you can configure this later[/yellow]")
    
    # Listener domain
    console.print("\n[bold cyan]Step 2: Callback Listener[/bold cyan]")
    console.print("[dim]Leave as 'auto' to use interactsh (recommended)[/dim]\n")
    
    listener = Prompt.ask(
        "Listener domain",
        default=config.get("listener_domain", "auto")
    )
    config["listener_domain"] = listener
    
    # Target scope
    console.print("\n[bold cyan]Step 3: Default Scope[/bold cyan]")
    console.print("[dim]Add domains to scan (comma-separated, supports wildcards)[/dim]\n")
    
    current_scope = config.get("allowed_scope", [])
    scope_str = Prompt.ask(
        "Allowed domains",
        default=", ".join(current_scope) if current_scope else ""
    )
    
    if scope_str:
        config["allowed_scope"] = [s.strip() for s in scope_str.split(",") if s.strip()]
    
    # Rate limiting
    console.print("\n[bold cyan]Step 4: Safety Settings[/bold cyan]")
    rate = Prompt.ask("Rate limit (requests/sec)", default=str(config.get("rate_limit", 10)))
    config["rate_limit"] = int(rate)
    
    max_subs = Prompt.ask("Max subdomains per domain", default=str(config.get("max_subdomains", 500)))
    config["max_subdomains"] = int(max_subs)
    
    depth = Prompt.ask("Crawl depth", default=str(config.get("crawl_depth", 3)))
    config["crawl_depth"] = int(depth)
    
    config["auto_report"] = Confirm.ask("Auto-generate reports on hits?", default=True)
    
    # Save config
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)
    
    console.print(Panel(
        f"[green]✓ Configuration saved to {CONFIG_PATH}[/green]\n\n"
        f"[dim]Next steps:[/dim]\n"
        f"  1. Run [cyan]bounty scope <program>[/cyan] to verify API access\n"
        f"  2. Run [cyan]bounty hunt <program> --dry-run[/cyan] to test the pipeline\n"
        f"  3. Run [cyan]bounty hunt <program>[/cyan] to start hunting!",
        title="✅ Setup Complete",
        border_style="green"
    ))


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    app()
