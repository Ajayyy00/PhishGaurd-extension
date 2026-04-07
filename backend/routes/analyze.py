"""
PhishGuard Analyze Routes
Handles URL and page content analysis endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from services.analyzer import AnalyzerService
from utils.validators import validate_analyze_request
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
        "risk_level": "safe|low|medium|high|critical",
        "is_phishing": boolean,
        "explanations": [...]
    }
    """
    try:
        # Parse and validate request
        data = request.get_json()
        
        if not data:
            raise APIError('Request body must be JSON', 400)
        
        # Validate input
        validation_error = validate_analyze_request(data)
        if validation_error:
            raise APIError(validation_error, 400)
        
        # Extract inputs
        url = data.get('url', '')
        text = data.get('text', '')
        dom = data.get('dom', {})
        
        current_app.logger.info(f"Analyzing URL: {url[:50]}...")
        
        # Run analysis
        analyzer = AnalyzerService()
        result = analyzer.analyze(url=url, text=text, dom=dom)
        
        current_app.logger.info(f"Analysis complete - Risk: {result.get('final_score', 0)}")
        
        return jsonify(result)
        
    except APIError as e:
        current_app.logger.warning(f"API Error: {e.message}")
        return jsonify({'error': e.message}), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
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
        data = request.get_json()
        
        if not data or 'urls' not in data:
            raise APIError('Missing required field: urls', 400)
        
        urls = data.get('urls', [])
        
        if not isinstance(urls, list):
            raise APIError('urls must be an array', 400)
        
        if len(urls) > 100:
            raise APIError('Maximum 100 URLs per batch', 400)
        
        analyzer = AnalyzerService()
        results = []
        
        for url in urls:
            result = analyzer.analyze(url=url, text='', dom={})
            results.append(result)
        
        return jsonify({'results': results})
        
    except APIError as e:
        return jsonify({'error': e.message}), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Batch error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
