"""
guardrails.py - Safety validation for BountyLedger.

Implements strict input validation to prevent targeting:
- Internal/private IP ranges (127.x, 10.x, 192.168.x, 172.16-31.x, 169.254.x)
- IPv6 loopback and private ranges (::1, fc00::, fe80::)
- Dangerous URI schemes (file://, gopher://, dict://, ldap://)
"""

import ipaddress
import re
import fnmatch
from urllib.parse import urlparse
from typing import Optional
from pydantic import BaseModel, field_validator


# ============================================================================
# Constants
# ============================================================================

# Dangerous schemes that should never be allowed
BLOCKED_SCHEMES = frozenset({
    "file",
    "gopher", 
    "dict",
    "ldap",
    "ldaps",
    "tftp",
    "data",  # Can be used for XSS/data exfil
})

# Private/internal IPv4 networks
PRIVATE_IPV4_NETWORKS = [
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("10.0.0.0/8"),       # Class A Private
    ipaddress.IPv4Network("172.16.0.0/12"),    # Class B Private
    ipaddress.IPv4Network("192.168.0.0/16"),   # Class C Private
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local
    ipaddress.IPv4Network("0.0.0.0/8"),        # This network
    ipaddress.IPv4Network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.IPv4Network("192.0.0.0/24"),     # IETF Protocol
    ipaddress.IPv4Network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved
]

# Private/internal IPv6 networks
PRIVATE_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::1/128"),          # Loopback
    ipaddress.IPv6Network("fc00::/7"),         # Unique local (ULA)
    ipaddress.IPv6Network("fe80::/10"),        # Link-local
    ipaddress.IPv6Network("ff00::/8"),         # Multicast
    ipaddress.IPv6Network("::ffff:0:0/96"),    # IPv4-mapped (check underlying)
]

# Hostnames that resolve to localhost
LOCALHOST_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "local",
    "127.0.0.1",
    "::1",
    "[::1]",
    "0.0.0.0",
    "0",
})


# ============================================================================
# Validation Result Model
# ============================================================================

class ValidationResult(BaseModel):
    """Result of a URL safety validation."""
    is_safe: bool
    url: str
    reason: Optional[str] = None
    
    def __bool__(self) -> bool:
        return self.is_safe


# ============================================================================
# Validator Class
# ============================================================================

class Validator:
    """
    URL safety validator with guardrails against internal/private targets.
    
    Usage:
        validator = Validator()
        result = validator.is_safe_target("http://example.com/api")
        if not result:
            print(f"Blocked: {result.reason}")
    """
    
    def __init__(self, allowed_schemes: Optional[set[str]] = None):
        """
        Initialize the validator.
        
        Args:
            allowed_schemes: Set of allowed URI schemes. Defaults to http/https only.
        """
        self.allowed_schemes = allowed_schemes or {"http", "https"}
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address is private/internal."""
        try:
            # Try IPv4 first
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in PRIVATE_IPV4_NETWORKS)
        except ipaddress.AddressValueError:
            pass
        
        try:
            # Try IPv6
            ip = ipaddress.IPv6Address(ip_str)
            
            # Check for IPv4-mapped IPv6 addresses
            if ip.ipv4_mapped:
                return self._is_private_ip(str(ip.ipv4_mapped))
            
            return any(ip in network for network in PRIVATE_IPV6_NETWORKS)
        except ipaddress.AddressValueError:
            pass
        
        return False
    
    def _extract_host(self, url: str) -> Optional[str]:
        """Extract the hostname from a URL."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            return host.lower() if host else None
        except Exception:
            return None
    
    def is_safe_target(self, url: str) -> ValidationResult:
        """
        Check if a URL is safe to target (not internal/private).
        
        Returns:
            ValidationResult with is_safe=True if target is external,
            False with reason if blocked.
        """
        if not url:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason="Empty URL provided"
            )
        
        # Parse the URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason=f"Invalid URL format: {e}"
            )
        
        # Check scheme
        scheme = parsed.scheme.lower()
        
        if not scheme:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason="No URL scheme provided (missing http:// or https://)"
            )
        
        if scheme in BLOCKED_SCHEMES:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason=f"Blocked scheme: {scheme}:// is not allowed"
            )
        
        if scheme not in self.allowed_schemes:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason=f"Scheme '{scheme}' not in allowed list: {self.allowed_schemes}"
            )
        
        # Extract and check hostname
        hostname = parsed.hostname
        
        if not hostname:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason="No hostname in URL"
            )
        
        hostname_lower = hostname.lower()
        
        # Check localhost aliases
        if hostname_lower in LOCALHOST_HOSTNAMES:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason=f"Localhost hostname blocked: {hostname}"
            )
        
        # Strip IPv6 brackets if present
        clean_host = hostname_lower.strip("[]")
        
        # Check if hostname is a direct IP address
        if self._is_private_ip(clean_host):
            return ValidationResult(
                is_safe=False,
                url=url,
                reason=f"Private/internal IP blocked: {hostname}"
            )
        
        # Check for DNS rebinding patterns (decimal IP encoding)
        # e.g., http://2130706433 = http://127.0.0.1
        if clean_host.isdigit():
            try:
                decimal_ip = int(clean_host)
                if 0 <= decimal_ip <= 0xFFFFFFFF:
                    # Convert to IP and check
                    ip_str = str(ipaddress.IPv4Address(decimal_ip))
                    if self._is_private_ip(ip_str):
                        return ValidationResult(
                            is_safe=False,
                            url=url,
                            reason=f"Decimal IP encoding blocked (resolves to {ip_str})"
                        )
            except (ValueError, ipaddress.AddressValueError):
                pass
        
        # Check for octal/hex IP encoding
        # e.g., 0x7f.0x0.0x0.0x1 or 0177.0.0.1
        octal_hex_pattern = re.compile(r'^(0x[0-9a-f]+|0[0-7]+)(\.(0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$', re.I)
        if octal_hex_pattern.match(clean_host):
            return ValidationResult(
                is_safe=False,
                url=url,
                reason="Octal/hex IP encoding pattern blocked"
            )
        
        # URL is safe
        return ValidationResult(is_safe=True, url=url)
    
    def check_scope(
        self,
        url: str,
        allowed_domains: list[str]
    ) -> ValidationResult:
        """
        Check if a URL is within the allowed scope.
        
        Args:
            url: The URL to check
            allowed_domains: List of allowed domain patterns (supports wildcards)
                            e.g., ["*.example.com", "api.target.com"]
        
        Returns:
            ValidationResult with is_safe=True if in scope.
        """
        # First check basic safety
        safety_check = self.is_safe_target(url)
        if not safety_check:
            return safety_check
        
        if not allowed_domains:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason="No allowed domains configured"
            )
        
        hostname = self._extract_host(url)
        if not hostname:
            return ValidationResult(
                is_safe=False,
                url=url,
                reason="Could not extract hostname from URL"
            )
        
        hostname_lower = hostname.lower()
        
        # Check against each allowed domain pattern
        for pattern in allowed_domains:
            pattern = pattern.lower().strip()
            
            # Handle wildcard patterns
            if pattern.startswith("*."):
                # Match subdomain or exact domain
                base_domain = pattern[2:]  # Remove "*."
                if hostname_lower == base_domain or hostname_lower.endswith("." + base_domain):
                    return ValidationResult(is_safe=True, url=url)
            else:
                # Exact match
                if hostname_lower == pattern:
                    return ValidationResult(is_safe=True, url=url)
                # Also try fnmatch for more complex patterns
                if fnmatch.fnmatch(hostname_lower, pattern):
                    return ValidationResult(is_safe=True, url=url)
        
        return ValidationResult(
            is_safe=False,
            url=url,
            reason=f"Domain '{hostname}' not in allowed scope: {allowed_domains}"
        )


# ============================================================================
# Convenience Functions
# ============================================================================

# Default global validator instance
_default_validator = Validator()


def is_safe_target(url: str) -> ValidationResult:
    """Check if a URL is safe using the default validator."""
    return _default_validator.is_safe_target(url)


def check_scope(url: str, allowed_domains: list[str]) -> ValidationResult:
    """Check if a URL is in scope using the default validator."""
    return _default_validator.check_scope(url, allowed_domains)


def validate_url(url: str, allowed_domains: Optional[list[str]] = None) -> ValidationResult:
    """
    Full validation: safety check + optional scope check.
    
    Args:
        url: URL to validate
        allowed_domains: If provided, also check scope
    
    Returns:
        ValidationResult
    """
    if allowed_domains:
        return check_scope(url, allowed_domains)
    return is_safe_target(url)
