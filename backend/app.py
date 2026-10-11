"""
PhishGuard Backend - Main Application Entry Point
Flask REST API for phishing detection
"""

import os
import logging
import re
from flask import Flask
from werkzeug.exceptions import HTTPException

from routes import register_routes
from utils.logger import setup_logging
from utils.security import install_security
from services.analyzer import AnalyzerService


def create_app(config_name: str = None, overrides=None) -> Flask:
    """
    Application factory for creating Flask app instances.
    
    Args:
        config_name: Configuration environment (development/production/testing)
        
    Returns:
        Configured Flask application instance
    """
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'production')
    app.config.from_mapping(
        SECRET_KEY=os.getenv('SECRET_KEY'),
        DEBUG=config_name == 'development',
        TESTING=config_name == 'testing',
        JSON_SORT_KEYS=False,
        API_TOKEN=os.getenv('PHISHGUARD_API_TOKEN', ''),
        EXTENSION_ORIGINS=[s.strip() for s in os.getenv('PHISHGUARD_EXTENSION_ORIGINS', '').split(',') if s.strip()],
        MAX_CONTENT_LENGTH=262144,
        ANALYSIS_RATE_LIMIT=120,
        DETECTOR_TIMEOUT=20,
        CACHE_MAXSIZE=512,
        CACHE_TTL=86400,
    )
    if overrides:
        app.config.update(overrides)
    if any(not re.fullmatch(r'chrome-extension://[a-p]{32}', origin) for origin in app.config['EXTENSION_ORIGINS']):
        raise ValueError('Only exact chrome-extension://<32-letter ID> origins are allowed')
    
    # Setup logging
    setup_logging(app, config_name)
    
    install_security(app)
    app.extensions['analyzer'] = AnalyzerService(cache_size=app.config['CACHE_MAXSIZE'],
        cache_ttl=app.config['CACHE_TTL'], timeout=app.config['DETECTOR_TIMEOUT'])

    @app.errorhandler(HTTPException)
    def http_error(error):
        return {'error': error.name}, error.code

    @app.errorhandler(Exception)
    def internal_error(error):
        app.logger.error('Unhandled API failure (%s)', type(error).__name__)
        return {'error': 'Internal server error'}, 500
    
    # Register all routes
    register_routes(app)
    
    # Health check route
    @app.route('/health')
    def health_check():
        return {'status': 'healthy', 'service': 'phishguard-api'}
    
    app.logger.info(f"PhishGuard API initialized in {config_name} mode")
    
    return app


# Create application instance
app = create_app()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    
    print(f"Starting PhishGuard API on port {port}...")
    app.run(host='127.0.0.1', port=port, debug=debug)
