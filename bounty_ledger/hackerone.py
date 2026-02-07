"""
hackerone.py - HackerOne API client for BountyLedger.

Fetches program scopes, searches for programs, and retrieves
bounty information via the HackerOne API v1.
"""

import json
import urllib.request
import urllib.error
import base64
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


API_BASE = "https://api.hackerone.com/v1"


@dataclass
class ScopeAsset:
    """A single in-scope asset from a HackerOne program."""
    asset_type: str        # URL, WILDCARD, IP_ADDRESS, etc.
    asset_identifier: str  # e.g., "*.shopify.com"
    eligible_for_bounty: bool
    eligible_for_submission: bool
    instruction: str = ""
    max_severity: str = ""
    
    @property
    def is_web(self) -> bool:
        """Check if this is a web-accessible asset."""
        return self.asset_type in ("URL", "WILDCARD")
    
    @property
    def domain_pattern(self) -> str:
        """Convert to a domain pattern for scope checking."""
        identifier = self.asset_identifier.lower()
        # Strip protocol if present
        for prefix in ("https://", "http://"):
            if identifier.startswith(prefix):
                identifier = identifier[len(prefix):]
        # Strip trailing path
        identifier = identifier.split("/")[0]
        return identifier


@dataclass
class ProgramInfo:
    """HackerOne program information."""
    handle: str
    name: str
    url: str
    offers_bounties: bool
    state: str  # open, paused, etc.
    scope_assets: list[ScopeAsset] = field(default_factory=list)
    
    @property
    def web_domains(self) -> list[str]:
        """Get all in-scope web domain patterns."""
        return [
            asset.domain_pattern
            for asset in self.scope_assets
            if asset.is_web and asset.eligible_for_submission
        ]
    
    @property
    def bounty_domains(self) -> list[str]:
        """Get only domains eligible for monetary bounty."""
        return [
            asset.domain_pattern
            for asset in self.scope_assets
            if asset.is_web and asset.eligible_for_bounty
        ]


class HackerOneClient:
    """
    HackerOne API v1 client.
    
    Requires an API token and username. Generate your token at:
    https://hackerone.com/settings/api_token/edit
    """
    
    def __init__(self, username: str = "", api_token: str = ""):
        self.username = username
        self.api_token = api_token
    
    @classmethod
    def from_config(cls, config_path: Optional[Path] = None) -> "HackerOneClient":
        """Create client from config.json."""
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config.json"
        
        if not config_path.exists():
            return cls()
        
        with open(config_path) as f:
            config = json.load(f)
        
        return cls(
            username=config.get("hackerone_username", ""),
            api_token=config.get("hackerone_api_token", ""),
        )
    
    @property
    def is_configured(self) -> bool:
        return bool(self.username and self.api_token)
    
    def _auth_header(self) -> str:
        """Generate Basic auth header."""
        credentials = f"{self.username}:{self.api_token}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
    def _request(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """Make an authenticated API request."""
        if not self.is_configured:
            raise ValueError(
                "HackerOne API not configured. Add 'hackerone_username' and "
                "'hackerone_api_token' to config.json, or run 'bounty setup'."
            )
        
        url = f"{API_BASE}{endpoint}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"
        
        req = urllib.request.Request(url)
        req.add_header("Authorization", self._auth_header())
        req.add_header("Accept", "application/json")
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            raise RuntimeError(
                f"HackerOne API error {e.code}: {e.reason}\n{body}"
            )
    
    def get_program_scope(self, handle: str) -> ProgramInfo:
        """
        Fetch program info and in-scope assets.
        
        Args:
            handle: Program handle (e.g., 'shopify')
        
        Returns:
            ProgramInfo with scope assets
        """
        # Get program info
        data = self._request(f"/hackers/programs/{handle}")
        program_data = data.get("data", {})
        attributes = program_data.get("attributes", {})
        
        program = ProgramInfo(
            handle=handle,
            name=attributes.get("name", handle),
            url=f"https://hackerone.com/{handle}",
            offers_bounties=attributes.get("offers_bounties", False),
            state=attributes.get("state", "unknown"),
        )
        
        # Get structured scopes
        try:
            scope_data = self._request(
                f"/hackers/programs/{handle}/structured_scopes",
                params={"page[size]": "100"}
            )
            
            for item in scope_data.get("data", []):
                attrs = item.get("attributes", {})
                asset = ScopeAsset(
                    asset_type=attrs.get("asset_type", ""),
                    asset_identifier=attrs.get("asset_identifier", ""),
                    eligible_for_bounty=attrs.get("eligible_for_bounty", False),
                    eligible_for_submission=attrs.get("eligible_for_submission", True),
                    instruction=attrs.get("instruction", ""),
                    max_severity=attrs.get("max_severity", ""),
                )
                program.scope_assets.append(asset)
        
        except Exception:
            # Scope endpoint might not be available for all programs
            pass
        
        return program
    
    def search_programs(
        self,
        keyword: str = "",
        bounties_only: bool = True,
    ) -> list[dict]:
        """
        Search for bug bounty programs.
        
        Args:
            keyword: Search keyword
            bounties_only: Only return programs offering bounties
        
        Returns:
            List of program summaries
        """
        params = {"page[size]": "25"}
        if bounties_only:
            params["filter[offers_bounties]"] = "true"
        
        data = self._request("/hackers/programs", params=params)
        
        programs = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            programs.append({
                "handle": attrs.get("handle", ""),
                "name": attrs.get("name", ""),
                "offers_bounties": attrs.get("offers_bounties", False),
                "state": attrs.get("state", ""),
                "url": f"https://hackerone.com/{attrs.get('handle', '')}",
            })
        
        if keyword:
            keyword_lower = keyword.lower()
            programs = [
                p for p in programs
                if keyword_lower in p["name"].lower() or keyword_lower in p["handle"].lower()
            ]
        
        return programs


# Convenience function
def get_scope(handle: str, config_path: Optional[Path] = None) -> ProgramInfo:
    """Quick scope fetch using config credentials."""
    client = HackerOneClient.from_config(config_path)
    return client.get_program_scope(handle)
