"""
PhishGuard Input Validators
Request validation functions
"""

from typing import Optional, Dict, Any


def validate_analyze_request(data: Dict[str, Any]) -> Optional[str]:
    """
    Validate the analyze endpoint request body.
    
    Args:
        data: Request JSON data
        
    Returns:
        Error message string if validation fails, None if valid
    """
    if not data:
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
    
    # Text is optional but must be string if provided
    text = data.get('text')
    if text is not None and not isinstance(text, str):
        return 'text must be a string'
    
    if text and len(text) > 100000:
        return 'text exceeds maximum length of 100000 characters'
    
    # DOM is optional but must be dict/object if provided
    dom = data.get('dom')
    if dom is not None and not isinstance(dom, dict):
        return 'dom must be an object'
    
    return None


def validate_batch_request(data: Dict[str, Any]) -> Optional[str]:
    """
    Validate the batch analyze endpoint request body.
    
    Args:
        data: Request JSON data
        
    Returns:
        Error message string if validation fails, None if valid
    """
    if not data:
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
        if not isinstance(url, str):
            return f'urls[{i}] must be a string'
        if not url.startswith(('http://', 'https://')):
            return f'urls[{i}] must start with http:// or https://'
    
    return None
