"""
PhishGuard Status Routes
Handles API status and info endpoints
"""

from flask import Blueprint, jsonify, current_app

status_bp = Blueprint('status', __name__)


@status_bp.route('/status', methods=['GET'])
def api_status():
    """
    Get API status and model information.
    """
    from services import url_detector, nlp_detector
    url_loaded = url_detector._detector_instance is not None and url_detector._detector_instance.model is not None
    nlp_loaded = nlp_detector._nlp_detector_instance is not None and nlp_detector._nlp_detector_instance.model is not None
    return jsonify({
        'status': 'operational', 'version': '1.1.0', 'model_loaded': url_loaded and nlp_loaded,
        'model_version': current_app.extensions['analyzer'].model_revision,
        'analysis_mode': 'url_nlp_dom',
        'models': {'url': 'loaded' if url_loaded else 'not_loaded', 'nlp': 'loaded' if nlp_loaded else 'not_loaded'},
        'capabilities': {'url_analysis': True, 'nlp_analysis': True, 'dom_analysis': True, 'ml_inference': True},
        'cache': current_app.extensions['analyzer']._cache.stats(),
    })


@status_bp.route('/info', methods=['GET'])
def api_info():
    """
    Get API information and available endpoints.
    """
    return jsonify({
        'name': 'PhishGuard API',
        'description': 'Real-time phishing detection API',
        'version': '1.1.0',
        'endpoints': {
            'POST /api/analyze': 'Analyze URL, text, and DOM',
            'POST /api/batch': 'Batch analyze multiple URLs',
            'GET /api/status': 'Get API status',
            'GET /api/info': 'Get API information',
            'GET /health': 'Health check'
        }
    })
