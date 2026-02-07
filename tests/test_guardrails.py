"""
Tests for guardrails.py - Safety validation.
"""

import pytest
from bounty_ledger.guardrails import Validator, is_safe_target, check_scope


class TestValidator:
    """Test the Validator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = Validator()
    
    # ========================================================================
    # Private IP Blocking Tests
    # ========================================================================
    
    def test_blocks_localhost(self):
        """Should block localhost."""
        result = self.validator.is_safe_target("http://localhost/admin")
        assert not result.is_safe
        assert "localhost" in result.reason.lower()
    
    def test_blocks_127_0_0_1(self):
        """Should block 127.0.0.1."""
        result = self.validator.is_safe_target("http://127.0.0.1/api")
        assert not result.is_safe
        assert "blocked" in result.reason.lower()
    
    def test_blocks_loopback_range(self):
        """Should block entire 127.x.x.x range."""
        result = self.validator.is_safe_target("http://127.1.2.3:8080/test")
        assert not result.is_safe
    
    def test_blocks_10_x_range(self):
        """Should block 10.0.0.0/8 private range."""
        assert not self.validator.is_safe_target("http://10.0.0.1/internal").is_safe
        assert not self.validator.is_safe_target("http://10.255.255.255/api").is_safe
    
    def test_blocks_172_16_range(self):
        """Should block 172.16.0.0/12 private range."""
        assert not self.validator.is_safe_target("http://172.16.0.1/").is_safe
        assert not self.validator.is_safe_target("http://172.31.255.255/").is_safe
        # 172.32.x.x should be allowed
        result = self.validator.is_safe_target("http://172.32.0.1/")
        assert result.is_safe
    
    def test_blocks_192_168_range(self):
        """Should block 192.168.0.0/16 private range."""
        assert not self.validator.is_safe_target("http://192.168.1.1/router").is_safe
        assert not self.validator.is_safe_target("http://192.168.255.255/").is_safe
    
    def test_blocks_169_254_link_local(self):
        """Should block 169.254.0.0/16 link-local range."""
        assert not self.validator.is_safe_target("http://169.254.1.1/").is_safe
        # AWS metadata
        assert not self.validator.is_safe_target("http://169.254.169.254/latest/meta-data/").is_safe
    
    def test_blocks_ipv6_loopback(self):
        """Should block IPv6 loopback ::1."""
        assert not self.validator.is_safe_target("http://[::1]/admin").is_safe
    
    # ========================================================================
    # Dangerous Scheme Tests
    # ========================================================================
    
    def test_blocks_file_scheme(self):
        """Should block file:// scheme."""
        result = self.validator.is_safe_target("file:///etc/passwd")
        assert not result.is_safe
        assert "scheme" in result.reason.lower()
    
    def test_blocks_gopher_scheme(self):
        """Should block gopher:// scheme."""
        result = self.validator.is_safe_target("gopher://evil.com/")
        assert not result.is_safe
    
    def test_blocks_dict_scheme(self):
        """Should block dict:// scheme."""
        result = self.validator.is_safe_target("dict://localhost:11211/")
        assert not result.is_safe
    
    def test_blocks_ldap_scheme(self):
        """Should block ldap:// scheme."""
        result = self.validator.is_safe_target("ldap://attacker.com/")
        assert not result.is_safe
    
    # ========================================================================
    # DNS Rebinding Protection Tests
    # ========================================================================
    
    def test_blocks_decimal_ip_encoding(self):
        """Should block decimal IP encoding (2130706433 = 127.0.0.1)."""
        result = self.validator.is_safe_target("http://2130706433/")
        assert not result.is_safe
        assert "decimal" in result.reason.lower() or "127.0.0.1" in result.reason
    
    def test_blocks_octal_ip_encoding(self):
        """Should block octal IP patterns."""
        result = self.validator.is_safe_target("http://0177.0.0.1/")
        assert not result.is_safe
    
    # ========================================================================
    # Valid External URLs Tests
    # ========================================================================
    
    def test_allows_external_https(self):
        """Should allow external HTTPS URLs."""
        result = self.validator.is_safe_target("https://example.com/api")
        assert result.is_safe
    
    def test_allows_external_http(self):
        """Should allow external HTTP URLs."""
        result = self.validator.is_safe_target("http://api.target.com/v1/users")
        assert result.is_safe
    
    def test_allows_public_ip(self):
        """Should allow public IP addresses."""
        result = self.validator.is_safe_target("http://8.8.8.8/dns")
        assert result.is_safe
    
    # ========================================================================
    # Edge Cases
    # ========================================================================
    
    def test_empty_url(self):
        """Should reject empty URL."""
        result = self.validator.is_safe_target("")
        assert not result.is_safe
    
    def test_no_scheme(self):
        """Should reject URL without scheme."""
        result = self.validator.is_safe_target("example.com/api")
        assert not result.is_safe
    
    def test_no_hostname(self):
        """Should reject URL without hostname."""
        result = self.validator.is_safe_target("http:///path")
        assert not result.is_safe


class TestScopeChecking:
    """Test scope validation."""
    
    def setup_method(self):
        self.validator = Validator()
    
    def test_exact_domain_match(self):
        """Should allow exact domain match."""
        result = self.validator.check_scope(
            "https://api.target.com/v1",
            ["api.target.com"]
        )
        assert result.is_safe
    
    def test_wildcard_subdomain_match(self):
        """Should allow wildcard subdomain match."""
        result = self.validator.check_scope(
            "https://www.target.com/page",
            ["*.target.com"]
        )
        assert result.is_safe
    
    def test_wildcard_matches_base_domain(self):
        """Wildcard should also match base domain."""
        result = self.validator.check_scope(
            "https://target.com/",
            ["*.target.com"]
        )
        assert result.is_safe
    
    def test_rejects_out_of_scope(self):
        """Should reject URLs not in scope."""
        result = self.validator.check_scope(
            "https://evil.com/callback",
            ["*.target.com"]
        )
        assert not result.is_safe
        assert "not in allowed scope" in result.reason
    
    def test_multiple_allowed_domains(self):
        """Should check against multiple allowed domains."""
        allowed = ["*.meta.com", "*.fb.com", "api.instagram.com"]
        
        assert self.validator.check_scope("https://www.meta.com/", allowed).is_safe
        assert self.validator.check_scope("https://api.fb.com/v1", allowed).is_safe
        assert self.validator.check_scope("https://api.instagram.com/", allowed).is_safe
        assert not self.validator.check_scope("https://evil.com/", allowed).is_safe
    
    def test_scope_check_includes_safety_check(self):
        """Scope check should also perform safety validation."""
        result = self.validator.check_scope(
            "http://127.0.0.1/",
            ["*.target.com"]
        )
        assert not result.is_safe
        # Reason should mention blocked
        assert "blocked" in result.reason.lower()


# ============================================================================
# Convenience Function Tests
# ============================================================================

class TestConvenienceFunctions:
    """Test module-level convenience functions."""
    
    def test_is_safe_target_function(self):
        """Test is_safe_target convenience function."""
        assert is_safe_target("https://google.com").is_safe
        assert not is_safe_target("http://localhost").is_safe
    
    def test_check_scope_function(self):
        """Test check_scope convenience function."""
        result = check_scope("https://app.target.com/api", ["*.target.com"])
        assert result.is_safe


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
