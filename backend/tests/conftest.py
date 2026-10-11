import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from app import create_app


@pytest.fixture
def app():
    return create_app('testing', {'API_TOKEN': secrets.token_urlsafe(32),
        'EXTENSION_ORIGINS': ['chrome-extension://' + 'a' * 32]})


@pytest.fixture
def client(app):
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer ' + app.config['API_TOKEN']
    return client


@pytest.fixture
def service(monkeypatch):
    from services.analyzer import AnalyzerService
    service = AnalyzerService(timeout=.1)
    monkeypatch.setattr(service, '_analyze_url', lambda url: {'risk': 20, 'explanations': [], 'features': {}})
    monkeypatch.setattr(service, '_analyze_text', lambda text: {'risk': 60, 'explanations': [], 'suspicious_phrases': ['urgent']})
    monkeypatch.setattr(service, '_analyze_dom', lambda dom, url: {'risk': 80, 'explanations': []})
    monkeypatch.setattr(service, '_get_url_explanations', lambda url: [])
    return service
