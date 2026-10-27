"""
PhishGuard Analyze Routes
Handles URL and page content analysis endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from utils.validators import validate_analyze_request, validate_batch_request
from utils.errors import APIError

analyze_bp = Blueprint('analyze', __name__)


@analyze_bp.route('/analyze', methods=['POST'])
def analyze():
    """
    Analyze URL, text content, and DOM structure for phishing indicators.
    
    Expected JSON body:
    {
        "url": "https://example.com",
        "text": "visible page text content",
        "dom": { ... dom fingerprint ... }
    }
    
    Returns:
    {
        "url_risk": 0-100,
        "nlp_risk": 0-100,
        "dom_risk": 0-100,
        "final_score": 0-100,
        "risk_level": "safe|suspicious|dangerous|unknown",
        "is_phishing": boolean,
        "explanations": [...]
    }
    """
    try:
        # Parse and validate request
        data = request.get_json(silent=True)
        
        if not data:
            raise APIError('Request body must be JSON', 400)
        
        # Accept documented legacy field names without routing to the old heuristic API.
        if isinstance(data, dict):
            data = dict(data)
            if 'text' not in data and 'content' in data: data['text'] = data['content']
            if 'dom' not in data and 'dom_fingerprint' in data: data['dom'] = data['dom_fingerprint']
            if 'force_refresh' not in data and 'rescan' in data: data['force_refresh'] = data['rescan']
            # Legacy clients submit form metadata at the top level. Keep the
            # original fields for validation and forward them to DOM analysis.
            if 'forms' in data and isinstance(data.get('dom', {}), dict):
                data['dom'] = dict(data.get('dom', {}))
                data['dom'].setdefault('forms', data['forms'])
        # Validate input
        validation_error = validate_analyze_request(data)
        if validation_error:
            raise APIError(validation_error, 400)
        
        # Extract inputs
        url = data.get('url', '')
        text = data.get('text', '')
        dom = data.get('dom', {})
        
        current_app.logger.info("Analysis request accepted")
        
        # Run analysis
        analyzer = current_app.extensions['analyzer']
        result = analyzer.analyze(url=url, text=text, dom=dom, force_refresh=data.get('force_refresh', False))
        
        current_app.logger.info(f"Analysis complete - Risk: {result.get('final_score', 0)}")
        
        return jsonify(result)
        
    except APIError as e:
        current_app.logger.warning(f"API Error: {e.message}")
        return jsonify({'error': e.message}), e.status_code
        
    except Exception as e:
        current_app.logger.error("Analysis failure (%s)", type(e).__name__)
        return jsonify({'error': 'Internal server error'}), 500


@analyze_bp.route('/batch', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple URLs in a single request.
    
    Expected JSON body:
    {
        "urls": ["url1", "url2", ...]
    }
    """
    try:
        data = request.get_json(silent=True)
        
        validation_error = validate_batch_request(data)
        if validation_error:
            raise APIError(validation_error, 400)
        urls = data['urls']

        analyzer = current_app.extensions['analyzer']
        results = []
        
        for url in urls:
            try:
                result = analyzer.analyze(url=url, text='', dom={})
            except Exception as error:
                current_app.logger.error('Batch item failed (%s)', type(error).__name__)
                result = {'url': url, 'error': 'Analysis unavailable', 'risk_level': 'unknown',
                          'final_score': None, 'degraded': True}
            results.append(result)
        
        return jsonify({'results': results})
        
    except APIError as e:
        return jsonify({'error': e.message}), e.status_code
        
    except Exception as e:
        current_app.logger.error("Batch failure (%s)", type(e).__name__)
        return jsonify({'error': 'Internal server error'}), 500
