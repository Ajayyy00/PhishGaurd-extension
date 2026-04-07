"""
PhishGuard Configuration Settings
Environment-specific configuration classes
"""

import os
from dataclasses import dataclass


@dataclass
class BaseConfig:
    """Base configuration"""
    SECRET_KEY: str = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG: bool = False
    TESTING: bool = False
    
    # Model paths
    MODEL_DIR: str = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'saved')
    
    # API settings
    API_VERSION: str = '1.0.0'
    MAX_BATCH_SIZE: int = 100


@dataclass
class DevelopmentConfig(BaseConfig):
    """Development configuration"""
    DEBUG: bool = True


@dataclass
class ProductionConfig(BaseConfig):
    """Production configuration"""
    DEBUG: bool = False


@dataclass
class TestingConfig(BaseConfig):
    """Testing configuration"""
    TESTING: bool = True
    DEBUG: bool = True


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
