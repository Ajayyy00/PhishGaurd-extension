"""
PhishGuard Backend Application
Real-Time Scam & Phishing Detection API
"""

from flask import Flask
from flask_cors import CORS


def create_app(config_name: str = 'development') -> Flask:
    """
    Application factory for creating Flask app instances.
    
    Args:
        config_name: Configuration environment name
        
    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Enable CORS for extension communication
    CORS(app, origins=['chrome-extension://*'])
    
    # Load configuration
    app.config.from_mapping(
        SECRET_KEY='dev',
        DEBUG=config_name == 'development'
    )
    
    # Register blueprints
    from app.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Health check route
    @app.route('/health')
    def health_check():
        return {'status': 'healthy', 'service': 'phishguard-api'}
    
    return app
