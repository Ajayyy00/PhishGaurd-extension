"""Local-client bearer authentication, exact browser origins and work limits."""
import hmac
import time
from collections import deque
from threading import Lock
from urllib.parse import urlsplit
from flask import request, jsonify


class RateLimit:
    def __init__(self, limit=120, window=60, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self.events = deque()
        self.lock = Lock()

    def allow(self, cost=1):
        with self.lock:
            now = self.clock()
            while self.events and self.events[0] <= now - self.window:
                self.events.popleft()
            if len(self.events) + cost > self.limit:
                return False
            self.events.extend([now] * cost)
            return True


def install_security(app):
    limiter = RateLimit(app.config['ANALYSIS_RATE_LIMIT'])
    app.extensions['rate_limit'] = limiter

    @app.before_request
    def authorize():
        # Host checking also prevents DNS-rebinding names from reaching this service.
        try:
            local_host = urlsplit('//' + request.host).hostname
        except ValueError:
            local_host = None
        if local_host not in ('127.0.0.1', 'localhost', '::1'):
            return jsonify(error='Invalid local host'), 403
        origin = request.headers.get('Origin')
        if origin and origin not in app.config['EXTENSION_ORIGINS']:
            return jsonify(error='Origin not authorized'), 403
        if request.method == 'OPTIONS':
            if not origin or request.headers.get('Access-Control-Request-Method') not in ('GET', 'POST'):
                return jsonify(error='Preflight not authorized'), 403
            headers = {h.strip().lower() for h in request.headers.get('Access-Control-Request-Headers', '').split(',') if h.strip()}
            if not headers <= {'authorization', 'content-type', 'accept'}:
                return jsonify(error='Preflight headers not authorized'), 403
            return '', 204
        if request.path == '/health':
            return None  # Liveness only, no model/configuration/user information.
        token = app.config['API_TOKEN']
        if len(token) < 32:
            return jsonify(error='Local API pairing is not configured'), 503
        supplied = request.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
            return jsonify(error='Unauthorized'), 401
        if request.path in ('/api/analyze', '/api/batch') and request.method == 'POST':
            # Charge every item, including malformed attempts; no client-ID cardinality attack.
            data = request.get_json(silent=True)
            cost = len(data.get('urls', [])) if request.path.endswith('/batch') and isinstance(data, dict) and isinstance(data.get('urls'), list) else 1
            if not limiter.allow(max(1, cost)):
                response = jsonify(error='Analysis rate limit exceeded')
                response.headers['Retry-After'] = '60'
                return response, 429

    @app.after_request
    def response_headers(response):
        origin = request.headers.get('Origin')
        if origin in app.config['EXTENSION_ORIGINS']:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Vary'] = 'Origin'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
