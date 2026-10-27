"""
PhishGuard Input Validators
Request validation functions
"""

from typing import Optional, Dict, Any
from urllib.parse import urlsplit
import json
import re


def validate_analyze_request(data: Dict[str, Any]) -> Optional[str]:
    """
    Validate the analyze endpoint request body.
    
    Args:
        data: Request JSON data
        
    Returns:
        Error message string if validation fails, None if valid
    """
    if not isinstance(data, dict) or not data:
        return 'Request body is required'
    
    # URL is required
    url = data.get('url')
    if not url:
        return 'Missing required field: url'
    
    if not isinstance(url, str):
        return 'url must be a string'
    
    if len(url) > 2048:
        return 'url exceeds maximum length of 2048 characters'
    
    # Validate URL format (basic check)
    if not url.startswith(('http://', 'https://')):
        return 'url must start with http:// or https://'
    try:
        parsed = urlsplit(url)
        if not parsed.hostname or re.search(r'[\s\x00-\x1f\x7f\\]', url):
            return 'url must contain a valid hostname and no whitespace or control characters'
        parsed.hostname.encode('idna')
        parsed.port
    except (ValueError, UnicodeError):
        return 'Invalid URL'
    
    # Text is optional but must be string if provided
    text = data.get('text')
    if 'text' in data and not isinstance(text, str):
        return 'text must be a string'
    
    if text and len(text) > 100000:
        return 'text exceeds maximum length of 100000 characters'

    if 'rescan' in data and type(data['rescan']) is not bool:
        return 'rescan must be boolean'
    if 'content' in data and (not isinstance(data['content'], str) or len(data['content']) > 100000):
        return 'content must be a string of at most 100000 characters'
    if 'forms' in data:
        forms = data['forms']
        if not isinstance(forms, list) or len(forms) > 100 or any(
            not isinstance(item, dict) or any(not isinstance(v, (str, bool)) or
            (isinstance(v, str) and len(v) > 2048) for v in item.values()) for item in forms):
            return 'forms must contain at most 100 bounded form objects'
    
    # DOM is optional but must be dict/object if provided
    dom = data.get('dom')
    if 'dom' in data and not isinstance(dom, dict):
        return 'dom must be an object'
    if dom:
        try:
            if len(json.dumps(dom, allow_nan=False).encode()) > 65536:
                return 'dom exceeds 65536 bytes'
        except (TypeError, ValueError, RecursionError):
            return 'Invalid DOM payload'
        stats = dom.get('stats', {})
        if not isinstance(stats, dict) or any(type(v) is not int or not 0 <= v <= 100000 for v in stats.values()):
            return 'DOM stats must contain bounded non-negative integer counts'
        for field in ('forms', 'inputs'):
            items = dom.get(field, [])
            if not isinstance(items, list) or len(items) > 100:
                return f'DOM {field} must be an array of at most 100 items'
            if any(not isinstance(item, dict) or any(not isinstance(v, (str, bool)) or (isinstance(v, str) and len(v) > 2048) for v in item.values()) for item in items):
                return f'Invalid DOM {field} item'
        for field in ('visibleText', 'title', 'headings', 'assets'):
            if field in dom and (not isinstance(dom[field], str) or len(dom[field]) > 10000):
                return f'Invalid DOM {field}'
    if 'force_refresh' in data and type(data['force_refresh']) is not bool:
        return 'force_refresh must be boolean'
    
    return None


def validate_batch_request(data: Dict[str, Any]) -> Optional[str]:
    """
    Validate the batch analyze endpoint request body.
    
    Args:
        data: Request JSON data
        
    Returns:
        Error message string if validation fails, None if valid
    """
    if not isinstance(data, dict) or not data:
        return 'Request body is required'
    
    urls = data.get('urls')
    if not urls:
        return 'Missing required field: urls'
    
    if not isinstance(urls, list):
        return 'urls must be an array'
    
    if len(urls) == 0:
        return 'urls array cannot be empty'
    
    if len(urls) > 100:
        return 'Maximum 100 URLs per batch request'
    
    for i, url in enumerate(urls):
        error = validate_analyze_request({'url': url})
        if error:
            return f'urls[{i}]: {error}'
    
    return None
