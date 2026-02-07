"""
harvester.py - Parameter scanning and content analysis for BountyLedger.

Scans text content (HTTP requests, source code, HAR files) to identify
potential sink parameters like URLs, callbacks, and redirects.
"""

import re
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from enum import Enum


class ParamContext(str, Enum):
    """Context where the parameter was found."""
    URL_QUERY = "query"
    POST_BODY = "body"
    HEADER = "header"
    JSON_KEY = "json"
    HTML_ATTR = "html"
    GENERIC = "generic"


@dataclass
class CandidateParam:
    """A candidate sink parameter found during scanning."""
    param_name: str
    context: ParamContext
    sample_value: Optional[str] = None
    line_number: Optional[int] = None
    confidence: float = 0.5  # 0.0 to 1.0
    
    def __repr__(self) -> str:
        return f"CandidateParam({self.param_name}, ctx={self.context.value}, conf={self.confidence:.2f})"


# ============================================================================
# Keyword Patterns
# ============================================================================

# High-confidence URL/redirect parameter keywords
URL_KEYWORDS = [
    r'url', r'uri', r'link', r'href', r'src',
    r'redirect', r'redir', r'return', r'next', r'goto', r'continue',
    r'callback', r'webhook', r'hook',
    r'feed', r'rss', r'atom',
    r'image', r'img', r'icon', r'avatar', r'photo', r'picture',
    r'file', r'path', r'load', r'fetch',
    r'target', r'dest', r'destination',
    r'site', r'domain', r'host',
    r'proxy', r'forward',
    r'endpoint', r'api',
    r'source', r'origin', r'ref', r'referer',
]

# Build regex patterns from keywords
PARAM_PATTERNS = [
    # Query string parameters: ?param_url=value or &param_url=value
    (re.compile(
        r'[?&]([a-zA-Z_][a-zA-Z0-9_]*(?:' + '|'.join(URL_KEYWORDS) + r')[a-zA-Z0-9_]*)=([^&\s]*)',
        re.IGNORECASE
    ), ParamContext.URL_QUERY, 0.8),
    
    # JSON keys: "keyUrl": "value" or "key_url": "value"
    (re.compile(
        r'"([a-zA-Z_][a-zA-Z0-9_]*(?:' + '|'.join(URL_KEYWORDS) + r')[a-zA-Z0-9_]*)"\s*:\s*"([^"]*)"',
        re.IGNORECASE
    ), ParamContext.JSON_KEY, 0.75),
    
    # Form data: param_url=value (in POST bodies)
    (re.compile(
        r'^([a-zA-Z_][a-zA-Z0-9_]*(?:' + '|'.join(URL_KEYWORDS) + r')[a-zA-Z0-9_]*)=(.*)$',
        re.IGNORECASE | re.MULTILINE
    ), ParamContext.POST_BODY, 0.7),
    
    # HTML attributes: src="..." href="..." action="..."
    (re.compile(
        r'\b(src|href|action|data-url|data-src|formaction)\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE
    ), ParamContext.HTML_ATTR, 0.6),
    
    # Generic keyword matches: anything_url, url_something, etc.
    (re.compile(
        r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:' + '|'.join(URL_KEYWORDS) + r')[a-zA-Z0-9_]*)\b',
        re.IGNORECASE
    ), ParamContext.GENERIC, 0.4),
]

# Patterns for extracting HTTP methods
METHOD_PATTERN = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+', re.IGNORECASE)


# ============================================================================
# Core Scanning Functions
# ============================================================================

def scan_content(text: str) -> list[CandidateParam]:
    """
    Scan raw text content for potential sink parameters.
    
    Args:
        text: Raw text (HTTP request, source code, etc.)
    
    Returns:
        List of CandidateParam objects with potential sinks
    """
    candidates: dict[str, CandidateParam] = {}  # Use dict to dedupe by param name
    
    for pattern, context, base_confidence in PARAM_PATTERNS:
        for match in pattern.finditer(text):
            param_name = match.group(1).lower()
            
            # Skip if it's just a keyword without actual parameter name
            if param_name in URL_KEYWORDS:
                param_name = match.group(0)  # Use full match
            
            # Get sample value if available
            sample_value = None
            if match.lastindex and match.lastindex >= 2:
                sample_value = match.group(2)[:100]  # Truncate long values
            
            # Calculate line number
            line_number = text[:match.start()].count('\n') + 1
            
            # Boost confidence for specific high-value patterns
            confidence = base_confidence
            param_lower = param_name.lower()
            
            if any(kw in param_lower for kw in ['redirect', 'callback', 'webhook', 'return']):
                confidence = min(confidence + 0.15, 1.0)
            if sample_value and sample_value.startswith(('http://', 'https://')):
                confidence = min(confidence + 0.1, 1.0)
            
            # Keep highest confidence match for each param
            if param_name not in candidates or candidates[param_name].confidence < confidence:
                candidates[param_name] = CandidateParam(
                    param_name=param_name,
                    context=context,
                    sample_value=sample_value,
                    line_number=line_number,
                    confidence=confidence
                )
    
    # Sort by confidence descending
    return sorted(candidates.values(), key=lambda c: -c.confidence)


def scan_file(file_path: Path) -> list[CandidateParam]:
    """
    Scan a file for potential sink parameters.
    
    Supports:
    - Plain text (HTTP requests, source code)
    - HAR files (JSON)
    
    Args:
        file_path: Path to the file
    
    Returns:
        List of CandidateParam objects
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    content = path.read_text(encoding='utf-8', errors='ignore')
    
    # Check if it's a HAR file
    if path.suffix.lower() == '.har' or (content.strip().startswith('{') and '"log"' in content):
        return scan_har_content(content)
    
    return scan_content(content)


def scan_har_content(har_json: str) -> list[CandidateParam]:
    """
    Parse and scan a HAR (HTTP Archive) file.
    
    Extracts URLs and POST body keys from all requests.
    
    Args:
        har_json: JSON content of HAR file
    
    Returns:
        List of CandidateParam objects
    """
    candidates: dict[str, CandidateParam] = {}
    
    try:
        har_data = json.loads(har_json)
    except json.JSONDecodeError:
        # Fall back to plain text scanning
        return scan_content(har_json)
    
    entries = har_data.get('log', {}).get('entries', [])
    
    for entry in entries:
        request = entry.get('request', {})
        
        # Scan URL
        url = request.get('url', '')
        if url:
            url_candidates = scan_content(url)
            for c in url_candidates:
                c.context = ParamContext.URL_QUERY
                if c.param_name not in candidates or candidates[c.param_name].confidence < c.confidence:
                    candidates[c.param_name] = c
        
        # Scan query string params
        for param in request.get('queryString', []):
            name = param.get('name', '').lower()
            value = param.get('value', '')
            
            # Check if name contains URL keywords
            if any(kw in name for kw in URL_KEYWORDS):
                confidence = 0.85
                if value.startswith(('http://', 'https://')):
                    confidence = 0.95
                
                candidates[name] = CandidateParam(
                    param_name=name,
                    context=ParamContext.URL_QUERY,
                    sample_value=value[:100],
                    confidence=confidence
                )
        
        # Scan POST data
        post_data = request.get('postData', {})
        
        # Form params
        for param in post_data.get('params', []):
            name = param.get('name', '').lower()
            value = param.get('value', '')
            
            if any(kw in name for kw in URL_KEYWORDS):
                confidence = 0.8
                if value.startswith(('http://', 'https://')):
                    confidence = 0.9
                
                candidates[name] = CandidateParam(
                    param_name=name,
                    context=ParamContext.POST_BODY,
                    sample_value=value[:100],
                    confidence=confidence
                )
        
        # Raw POST body (JSON)
        text = post_data.get('text', '')
        if text:
            body_candidates = scan_content(text)
            for c in body_candidates:
                if c.context == ParamContext.GENERIC:
                    c.context = ParamContext.JSON_KEY
                if c.param_name not in candidates or candidates[c.param_name].confidence < c.confidence:
                    candidates[c.param_name] = c
        
        # Scan headers for interesting values
        for header in request.get('headers', []):
            name = header.get('name', '').lower()
            value = header.get('value', '')
            
            # Look for headers that might contain URLs
            if name in ['referer', 'origin', 'location', 'x-forwarded-host']:
                candidates[name] = CandidateParam(
                    param_name=name,
                    context=ParamContext.HEADER,
                    sample_value=value[:100],
                    confidence=0.65
                )
    
    return sorted(candidates.values(), key=lambda c: -c.confidence)


def extract_http_method(text: str) -> Optional[str]:
    """Extract HTTP method from request text if present."""
    match = METHOD_PATTERN.search(text)
    return match.group(1).upper() if match else None


# ============================================================================
# Risk Assessment
# ============================================================================

def assess_risk(param: CandidateParam) -> str:
    """
    Assess the risk level of a candidate parameter.
    
    Returns: "Low", "Medium", "High", or "Critical"
    """
    name = param.param_name.lower()
    
    # Critical: Known dangerous patterns
    if any(kw in name for kw in ['callback', 'webhook', 'redirect', 'redir']):
        return "Critical"
    
    # High: Direct URL-like parameters
    if any(kw in name for kw in ['url', 'uri', 'link', 'href', 'src']):
        return "High"
    
    # Medium: Potential indirect references
    if any(kw in name for kw in ['target', 'dest', 'next', 'return', 'goto']):
        return "Medium"
    
    # Low: General patterns
    return "Low"
