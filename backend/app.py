"""
PhishGuard Backend - Main Application Entry Point
Flask REST API for phishing detection
"""

import os
import logging
from flask import Flask
from flask_cors import CORS

from routes import register_routes
from utils.logger import setup_logging


def create_app(config_name: str = None) -> Flask:
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
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    app.config.from_mapping(
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key'),
        DEBUG=config_name == 'development',
        TESTING=config_name == 'testing',
        JSON_SORT_KEYS=False
    )
    
    # Setup logging
    setup_logging(app, config_name)
    
    # Enable CORS for extension communication
    CORS(app, resources={
        r"/api/*": {
            "origins": ["*", "chrome-extension://*"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Accept"]
        }
    })
    
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
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print(f"Starting PhishGuard API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=debug)
