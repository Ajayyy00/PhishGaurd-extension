"""
PhishGuard Backend Entry Point
Run the Flask development server
"""

import os
from app import create_app

# Create application instance
app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print(f"Starting PhishGuard API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=debug)
