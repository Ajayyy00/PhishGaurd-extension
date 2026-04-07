"""
PhishGuard Routes Package
Registers all API route blueprints
"""

from flask import Flask
from .analyze import analyze_bp
from .status import status_bp


def register_routes(app: Flask) -> None:
    """
    Register all route blueprints with the Flask app.
    
    Args:
        app: Flask application instance
    """
    app.register_blueprint(analyze_bp, url_prefix='/api')
    app.register_blueprint(status_bp, url_prefix='/api')
    
    app.logger.info("Routes registered successfully")
