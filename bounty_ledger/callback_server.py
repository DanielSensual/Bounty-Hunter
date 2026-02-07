"""
Lightweight self-hosted callback server for SSRF canary detection.

Replaces Interactsh when public OAST servers are unavailable.
Logs every incoming HTTP request (GET/POST/PUT/DELETE/OPTIONS/HEAD)
and auto-correlates with BountyLedger canary UUIDs.
"""

import json
import uuid
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable


@dataclass
class CallbackHit:
    """A single incoming callback."""
    timestamp: str
    method: str
    path: str
    remote_ip: str
    headers: dict
    body: str
    canary_uuid: Optional[str] = None
    sink_id: Optional[int] = None

    def summary(self) -> str:
        tag = f" [canary:{self.canary_uuid}]" if self.canary_uuid else ""
        return f"[{self.timestamp}] {self.method} {self.path} from {self.remote_ip}{tag}"


@dataclass
class CallbackSession:
    """Manages a callback listening session."""
    base_url: str = ""
    hits: list[CallbackHit] = field(default_factory=list)
    canaries: dict[str, int] = field(default_factory=dict)  # uuid -> sink_id

    def generate_canary(self, sink_id: int) -> str:
        """Generate a unique canary URL tagged with a sink ID."""
        canary_id = str(uuid.uuid4())[:8]
        self.canaries[canary_id] = sink_id
        return f"{self.base_url}/c/{canary_id}"

    def match_canary(self, path: str) -> tuple[Optional[str], Optional[int]]:
        """Check if an incoming path matches a canary."""
        for cid, sid in self.canaries.items():
            if cid in path:
                return cid, sid
        return None, None


# Global session
_session = CallbackSession()
_on_hit: Optional[Callable[[CallbackHit], None]] = None


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs every request as a potential callback."""

    def _handle(self):
        # Read body if present
        body = ""
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                body = self.rfile.read(int(content_length)).decode("utf-8", errors="ignore")
            except Exception:
                body = "<read error>"

        # Extract headers
        headers = dict(self.headers)

        # Check for canary match
        canary_uuid, sink_id = _session.match_canary(self.path)

        hit = CallbackHit(
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=self.command,
            path=self.path,
            remote_ip=self.client_address[0],
            headers=headers,
            body=body[:2000],
            canary_uuid=canary_uuid,
            sink_id=sink_id,
        )

        _session.hits.append(hit)

        # Notify callback
        if _on_hit:
            _on_hit(hit)

        # Auto-update database if canary matched
        if canary_uuid and sink_id:
            try:
                from bounty_ledger import database as db
                test = db.get_test_by_uuid(canary_uuid)
                if test:
                    db.update_test_status(
                        test['id'], 'HIT',
                        notes=f"Auto-callback: {self.command} from {self.client_address[0]}"
                    )
            except Exception:
                pass

        # Respond with 200 OK (look like a normal server)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_OPTIONS(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_PATCH(self): self._handle()

    def log_message(self, format, *args):
        """Suppress default logging — we handle it ourselves."""
        pass


def start_server(
    port: int = 8888,
    base_url: str = "",
    on_hit: Optional[Callable[[CallbackHit], None]] = None,
    background: bool = True,
) -> tuple[HTTPServer, CallbackSession]:
    """
    Start the callback listener.

    Args:
        port: Local port to listen on
        base_url: Public URL (from ngrok/tunnel) for canary generation
        on_hit: Callback function for each incoming hit
        background: Run in background thread

    Returns:
        (server, session) tuple
    """
    global _session, _on_hit

    _session = CallbackSession(base_url=base_url or f"http://localhost:{port}")
    _on_hit = on_hit

    server = HTTPServer(("0.0.0.0", port), CallbackHandler)

    if background:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    else:
        server.serve_forever()

    return server, _session


def get_session() -> CallbackSession:
    """Get the current callback session."""
    return _session


def save_hits(path: Path):
    """Save all hits to a JSON file."""
    hits_data = [asdict(h) for h in _session.hits]
    path.write_text(json.dumps(hits_data, indent=2))


def deploy_canaries(session: CallbackSession, sink_ids: list[int]) -> dict[int, str]:
    """
    Generate canary URLs for a list of sink IDs.

    Returns:
        Dict mapping sink_id -> canary_url
    """
    canaries = {}
    for sid in sink_ids:
        url = session.generate_canary(sid)
        canaries[sid] = url
    return canaries
