"""
PhishGuard API Tests
Unit tests for REST API endpoints
"""

import pytest
from app import create_app


@pytest.fixture
def client():
    """Create test client"""
    app = create_app('testing')
    with app.test_client() as client:
        yield client


def test_health_check(client):
    """Test health check endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'


def test_api_status(client):
    """Test API status endpoint"""
    response = client.get('/api/status')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'operational'


def test_analyze_url_missing_url(client):
    """Test analyze endpoint with missing URL"""
    response = client.post('/api/analyze', json={})
    assert response.status_code == 400


def test_analyze_url_valid(client):
    """Test analyze endpoint with valid URL"""
    response = client.post('/api/analyze', json={
        'url': 'https://example.com'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'url' in data
    assert 'is_phishing' in data
