"""
PhishGuard Error Handling
Custom exception classes for API errors
"""


class APIError(Exception):
    """
    Custom exception for API errors with HTTP status codes.
    """
    
    def __init__(self, message: str, status_code: int = 400):
        """
        Initialize API error.
        
        Args:
            message: Error message to return to client
            status_code: HTTP status code (default 400)
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
    
    def to_dict(self):
        """Convert error to dictionary for JSON response."""
        return {
            'error': self.message,
            'status_code': self.status_code
        }


class ValidationError(APIError):
    """Validation error for invalid input data."""
    
    def __init__(self, message: str):
        super().__init__(message, 400)


class NotFoundError(APIError):
    """Resource not found error."""
    
    def __init__(self, message: str = 'Resource not found'):
        super().__init__(message, 404)


class InternalError(APIError):
    """Internal server error."""
    
    def __init__(self, message: str = 'Internal server error'):
        super().__init__(message, 500)
