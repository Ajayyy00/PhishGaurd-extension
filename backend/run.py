"""
PhishGuard Backend Entry Point
Run the Flask development server
"""

import os
from app import create_app

# Create application instance
app = create_app(os.getenv('FLASK_ENV', 'production'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    
    print(f"Starting PhishGuard API on port {port}...")
    app.run(host='127.0.0.1', port=port, debug=debug)
