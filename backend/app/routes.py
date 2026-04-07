"""
PhishGuard API Routes
Defines REST API endpoints for phishing detection
"""

from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
import re

api_bp = Blueprint('api', __name__)


@api_bp.route('/analyze', methods=['POST'])
def analyze_url():
    """
    Analyze a URL for phishing indicators.
    
    Expected JSON body:
        {
            "url": "https://example.com",
            "content": "optional page content",
            "dom_fingerprint": {...},
            "metadata": {...},
            "forms": [...],
            "links": {...}
        }
    
    Returns:
        JSON response with analysis results
    """
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'error': 'Missing required field: url'
        }), 400
    
    url = data.get('url', '')
    content = data.get('content', '')
    forms = data.get('forms', [])
    links = data.get('links', {})
    metadata = data.get('metadata', {})
    
    # Perform heuristic analysis
    analysis = analyze_url_heuristics(url, content, forms, links, metadata)
    
    return jsonify(analysis)


def analyze_url_heuristics(url: str, content: str, forms: list, links: dict, metadata: dict) -> dict:
    """
    Analyze URL and page content using heuristics.
    Returns risk assessment.
    """
    risk_score = 0
    risk_factors = []
    safe_factors = []
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        
        # === Protocol Analysis ===
        if parsed.scheme == 'https':
            safe_factors.append('secure_connection')
        elif parsed.scheme == 'http':
            risk_score += 15
            risk_factors.append('insecure_http')
        
        # === Hostname Analysis ===
        # IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            risk_score += 30
            risk_factors.append('ip_address_url')
        
        # Excessive subdomains
        subdomain_count = len(hostname.split('.'))
        if subdomain_count > 4:
            risk_score += 15
            risk_factors.append('excessive_subdomains')
        elif subdomain_count > 2:
            risk_score += 5
        
        # Long hostname
        if len(hostname) > 30:
            risk_score += 10
            risk_factors.append('long_hostname')
        
        # Suspicious characters in hostname
        if '-' in hostname and any(brand in hostname.lower() for brand in ['paypal', 'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 'bank']):
            risk_score += 25
            risk_factors.append('brand_impersonation')
        
        # === Path Analysis ===
        suspicious_paths = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm', 'password', 'credential']
        if any(p in path.lower() for p in suspicious_paths):
            risk_score += 5
            risk_factors.append('sensitive_path')
        
        # === Form Analysis ===
        if forms:
            has_password_form = any(f.get('hasPasswordField') for f in forms)
            has_external_action = any(f.get('isExternal') for f in forms)
            
            if has_password_form:
                if parsed.scheme != 'https':
                    risk_score += 20
                    risk_factors.append('password_over_http')
                if has_external_action:
                    risk_score += 25
                    risk_factors.append('external_form_action')
        
        # === Link Analysis ===
        if links:
            total_links = links.get('total', 0)
            external_links = links.get('external', 0)
            if total_links > 0:
                external_ratio = external_links / total_links
                if external_ratio > 0.8:
                    risk_score += 10
                    risk_factors.append('high_external_links')
        
        # === Content Analysis ===
        if content:
            urgency_phrases = ['act now', 'limited time', 'expire', 'suspend', 'verify immediately', 
                             'confirm your', 'update your', 'unusual activity', 'unauthorized']
            content_lower = content.lower()
            if any(phrase in content_lower for phrase in urgency_phrases):
                risk_score += 10
                risk_factors.append('urgency_language')
        
        # === Positive Indicators ===
        # Well-known safe domains
        safe_domains = ['google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'github.com',
                       'microsoft.com', 'apple.com', 'amazon.com', 'linkedin.com', 'wikipedia.org',
                       'stackoverflow.com', 'reddit.com', 'netflix.com', 'instagram.com']
        
        for safe_domain in safe_domains:
            if hostname.endswith(safe_domain) or hostname == safe_domain:
                risk_score = max(0, risk_score - 30)
                safe_factors.append('known_safe_domain')
                break
        
        # Cap the score
        risk_score = max(0, min(100, risk_score))
        
    except Exception as e:
        risk_score = 30
        risk_factors.append('parse_error')
    
    # Determine risk level
    if risk_score < 20:
        risk_level = 'safe'
    elif risk_score < 40:
        risk_level = 'low'
    elif risk_score < 60:
        risk_level = 'medium'
    elif risk_score < 80:
        risk_level = 'high'
    else:
        risk_level = 'critical'
    
    # Build features dict for frontend
    try:
        parsed = urlparse(url)
        features = {
            'protocol': parsed.scheme + ':',
            'hostname': parsed.hostname or '',
            'pathname': parsed.path or '/',
            'hasSubdomain': len((parsed.hostname or '').split('.')) > 2,
            'hostnameLength': len(parsed.hostname or ''),
            'pathDepth': len([p for p in (parsed.path or '').split('/') if p]),
            'hasQueryParams': bool(parsed.query),
            'riskFactors': risk_factors,
            'safeFactors': safe_factors
        }
    except:
        features = {'error': 'Could not parse URL'}
    
    return {
        'url': url,
        'is_phishing': risk_score > 70,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'confidence': 0.75 if risk_score < 50 else 0.85,
        'features': features,
        'explanation': generate_explanation(risk_level, risk_factors, safe_factors)
    }


def generate_explanation(risk_level: str, risk_factors: list, safe_factors: list) -> str:
    """Generate human-readable explanation"""
    if risk_level == 'safe':
        if 'known_safe_domain' in safe_factors:
            return 'This is a known trusted website'
        return 'No significant risk indicators detected'
    elif risk_level == 'low':
        return 'Minor risk indicators detected, but likely safe'
    elif risk_level == 'medium':
        return f'Some suspicious indicators: {", ".join(risk_factors[:2])}'
    elif risk_level == 'high':
        return f'Multiple risk factors detected: {", ".join(risk_factors[:3])}'
    else:
        return f'High risk! Detected: {", ".join(risk_factors)}'


@api_bp.route('/batch', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple URLs in a single request.
    """
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({
            'error': 'Missing required field: urls'
        }), 400
    
    urls = data.get('urls', [])
    results = [analyze_url_heuristics(url, '', [], {}, {}) for url in urls[:100]]
    
    return jsonify({'results': results})


@api_bp.route('/status', methods=['GET'])
def api_status():
    """
    Get API status and model information.
    """
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'model_loaded': False,
        'model_version': None,
        'analysis_mode': 'heuristic'
    })
