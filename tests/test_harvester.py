"""
Tests for harvester.py - Parameter scanning.
"""

import pytest
from bounty_ledger.harvester import (
    scan_content, 
    scan_har_content, 
    CandidateParam, 
    ParamContext,
    assess_risk
)


class TestScanContent:
    """Test the scan_content function."""
    
    def test_finds_url_query_params(self):
        """Should find URL parameters containing URL keywords."""
        text = "https://example.com/api?redirect_url=https://evil.com&name=test"
        
        candidates = scan_content(text)
        param_names = [c.param_name for c in candidates]
        
        assert "redirect_url" in param_names
    
    def test_finds_callback_params(self):
        """Should find callback parameters."""
        text = "POST /webhook\ncallback_url=https://attacker.com/hook"
        
        candidates = scan_content(text)
        param_names = [c.param_name for c in candidates]
        
        assert any("callback" in p for p in param_names)
    
    def test_finds_json_keys(self):
        """Should find JSON keys with URL keywords."""
        text = '''
        {
            "imageUrl": "https://cdn.example.com/pic.jpg",
            "webhookEndpoint": "https://hooks.example.com/notify",
            "username": "test"
        }
        '''
        
        candidates = scan_content(text)
        param_names = [c.param_name for c in candidates]
        
        assert any("image" in p.lower() for p in param_names)
        assert any("webhook" in p.lower() for p in param_names)
    
    def test_finds_html_attributes(self):
        """Should find HTML src/href attributes."""
        text = '''
        <img src="https://example.com/image.jpg">
        <a href="https://example.com/page">Link</a>
        <form action="/submit">
        '''
        
        candidates = scan_content(text)
        contexts = [c.context for c in candidates]
        
        assert ParamContext.HTML_ATTR in contexts
    
    def test_returns_sample_values(self):
        """Should include sample values when available."""
        text = "?target_url=https://example.com/callback"
        
        candidates = scan_content(text)
        
        assert len(candidates) > 0
        target_param = next((c for c in candidates if "target" in c.param_name.lower()), None)
        assert target_param is not None
        assert target_param.sample_value is not None
    
    def test_higher_confidence_for_redirects(self):
        """Should assign higher confidence to redirect parameters."""
        text = "https://example.com/api?redirect_url=https://x.com&name=test"
        
        candidates = scan_content(text)
        redirect_param = next((c for c in candidates if "redirect" in c.param_name.lower()), None)
        
        assert redirect_param is not None
        assert redirect_param.confidence >= 0.7
    
    def test_deduplicates_params(self):
        """Should deduplicate parameters, keeping highest confidence."""
        text = """
        ?callback_url=a
        "callback_url": "b"
        callback_url=c
        """
        
        candidates = scan_content(text)
        callback_params = [c for c in candidates if "callback" in c.param_name.lower()]
        
        # Should only have one entry per unique param name
        assert len(callback_params) == 1
    
    def test_empty_text(self):
        """Should handle empty text."""
        candidates = scan_content("")
        assert candidates == []
    
    def test_no_matches(self):
        """Should return empty list when no matches."""
        text = "This is just regular text with no URLs or parameters."
        candidates = scan_content(text)
        # May have some low-confidence matches, filter for high confidence
        high_conf = [c for c in candidates if c.confidence > 0.5]
        assert len(high_conf) == 0


class TestScanHarContent:
    """Test HAR file parsing."""
    
    def test_parses_har_query_strings(self):
        """Should extract URL parameters from HAR entries."""
        har_json = '''
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.com/v1/fetch",
                            "queryString": [
                                {"name": "image_url", "value": "https://cdn.example.com/pic.jpg"},
                                {"name": "format", "value": "json"}
                            ]
                        }
                    }
                ]
            }
        }
        '''
        
        candidates = scan_har_content(har_json)
        param_names = [c.param_name for c in candidates]
        
        assert "image_url" in param_names
    
    def test_parses_har_post_data(self):
        """Should extract POST parameters from HAR entries."""
        har_json = '''
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.com/submit",
                            "postData": {
                                "params": [
                                    {"name": "webhook_url", "value": "https://hooks.example.com"}
                                ]
                            }
                        }
                    }
                ]
            }
        }
        '''
        
        candidates = scan_har_content(har_json)
        param_names = [c.param_name for c in candidates]
        
        assert "webhook_url" in param_names
    
    def test_parses_har_json_body(self):
        """Should scan JSON body in POST data."""
        har_json = '''
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.com/api",
                            "postData": {
                                "text": "{\\"redirectUri\\": \\"https://callback.com\\"}"
                            }
                        }
                    }
                ]
            }
        }
        '''
        
        candidates = scan_har_content(har_json)
        param_names = [c.param_name for c in candidates]
        
        assert any("redirect" in p.lower() for p in param_names)
    
    def test_fallback_on_invalid_json(self):
        """Should fall back to text scanning on invalid JSON."""
        invalid_har = "This is not valid JSON but contains redirect_url=something"
        
        candidates = scan_har_content(invalid_har)
        param_names = [c.param_name for c in candidates]
        
        assert any("redirect" in p.lower() for p in param_names)


class TestRiskAssessment:
    """Test risk level assessment."""
    
    def test_critical_for_callback(self):
        """Callback parameters should be Critical."""
        param = CandidateParam(param_name="callback_url", context=ParamContext.URL_QUERY)
        assert assess_risk(param) == "Critical"
    
    def test_critical_for_webhook(self):
        """Webhook parameters should be Critical."""
        param = CandidateParam(param_name="webhookEndpoint", context=ParamContext.JSON_KEY)
        assert assess_risk(param) == "Critical"
    
    def test_critical_for_redirect(self):
        """Redirect parameters should be Critical."""
        param = CandidateParam(param_name="redirect", context=ParamContext.URL_QUERY)
        assert assess_risk(param) == "Critical"
    
    def test_high_for_url(self):
        """URL parameters should be High."""
        param = CandidateParam(param_name="imageUrl", context=ParamContext.JSON_KEY)
        assert assess_risk(param) == "High"
    
    def test_high_for_src(self):
        """src parameters should be High."""
        param = CandidateParam(param_name="src", context=ParamContext.HTML_ATTR)
        assert assess_risk(param) == "High"
    
    def test_medium_for_next(self):
        """next/return parameters should be Medium."""
        param = CandidateParam(param_name="next", context=ParamContext.URL_QUERY)
        assert assess_risk(param) == "Medium"
    
    def test_low_for_generic(self):
        """Generic matches should be Low."""
        param = CandidateParam(param_name="loadData", context=ParamContext.GENERIC)
        assert assess_risk(param) == "Low"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
