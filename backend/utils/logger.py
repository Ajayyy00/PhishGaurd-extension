"""
PhishGuard Logging Configuration
Setup logging for the application
"""

import logging
import sys
from flask import Flask


def setup_logging(app: Flask, config_name: str = 'development') -> None:
    """
    Configure logging for the Flask application.
    
    Args:
        app: Flask application instance
        config_name: Environment name (development/production/testing)
    """
    # Determine log level based on environment
    if config_name == 'production':
        log_level = logging.INFO
    elif config_name == 'testing':
        log_level = logging.WARNING
    else:
        log_level = logging.DEBUG
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set Flask app logger level
    app.logger.setLevel(log_level)
    
    # Reduce noise from werkzeug in debug mode
    if config_name == 'development':
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    app.logger.debug(f"Logging configured at level: {logging.getLevelName(log_level)}")
