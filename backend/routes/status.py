"""
PhishGuard Status Routes
Handles API status and info endpoints
"""

from flask import Blueprint, jsonify

status_bp = Blueprint('status', __name__)


@status_bp.route('/status', methods=['GET'])
def api_status():
    """
    Get API status and model information.
    """
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'model_loaded': False,
        'model_version': None,
        'analysis_mode': 'heuristic',
        'capabilities': {
            'url_analysis': True,
            'nlp_analysis': False,
            'dom_analysis': True,
            'ml_inference': False
        }
    })


@status_bp.route('/info', methods=['GET'])
def api_info():
    """
    Get API information and available endpoints.
    """
    return jsonify({
        'name': 'PhishGuard API',
        'description': 'Real-time phishing detection API',
        'version': '1.0.0',
        'endpoints': {
            'POST /api/analyze': 'Analyze URL, text, and DOM',
            'POST /api/batch': 'Batch analyze multiple URLs',
            'GET /api/status': 'Get API status',
            'GET /api/info': 'Get API information',
            'GET /health': 'Health check'
        }
    })
