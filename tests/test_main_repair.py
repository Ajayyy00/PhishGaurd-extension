"""Real model/API regressions; original backend/tests remain byte-for-byte intact."""
import sys
from pathlib import Path
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))


@pytest.fixture
def client():
    from app import create_app
    with create_app('testing').test_client() as client:
        yield client


@pytest.mark.parametrize('url', ['javascript:alert(1)', 'data:text/plain,test', 'file:///tmp/test', 'ftp://example.com', 'http://'])
def test_authenticated_invalid_scheme(client, url):
    assert client.post('/api/analyze', json={'url': url}).status_code == 400


@pytest.mark.parametrize('endpoint', ['/api/status', '/api/info', '/api/analyze', '/api/batch'])
def test_authentication_is_not_bypassed_in_testing(client, endpoint):
    response = client.open(endpoint, method='POST' if endpoint.endswith(('analyze', 'batch')) else 'GET',
                           json={'url': 'https://example.com'}, headers={'Authorization': ''})
    assert response.status_code == 401


def test_default_startup_loads_both_models(client):
    status = client.get('/api/status').get_json()
    assert status['model_loaded'] and status['analysis_mode'] == 'url_nlp_dom'
    assert status['models'] == {'url': 'loaded', 'nlp': 'loaded'}


def test_legacy_contract_and_rescan(client):
    payload = {'url': 'https://example.org/legacy', 'content': 'Urgent! Verify your account immediately. Enter your password.',
               'forms': [{'hasPasswordField': True, 'isExternal': True}]}
    first = client.post('/api/analyze', json=payload).get_json()
    assert first['analysis_stage'] == 'full' and first['nlp_risk'] > 0 and first['dom_risk'] > 0
    assert first['risk_score'] == first['final_score']
    assert first['reasons'] == [item['message'] for item in first['explanations']]
    assert client.post('/api/analyze', json=payload).get_json()['cached'] is True
    assert client.post('/api/analyze', json={**payload, 'rescan': True}).get_json()['cached'] is False


@pytest.mark.parametrize('extra', [{'forms': 'bad'}, {'forms': [False]}, {'rescan': 'true'}, {'force_refresh': 1}, {'content': 9}])
def test_legacy_validation(client, extra):
    assert client.post('/api/analyze', json={'url': 'https://example.com', **extra}).status_code == 400


def test_url_only_to_full_has_independent_cache_entries(client):
    base = {'url': 'https://example.org/stage-regression'}
    first = client.post('/api/analyze', json=base).get_json()
    assert first['final_score'] == first['url_risk'] and first['nlp_risk'] is None
    full = client.post('/api/analyze', json={**base, 'text': 'Urgent! Verify your account immediately. Confirm your identity.',
                                           'dom': {'title': 'PayPal', 'inputs': [{'type': 'password'}]}}).get_json()
    assert full['analysis_stage'] == 'full' and full['nlp_risk'] > 0 and full['dom_risk'] > 0
    assert not full['cached']


def test_crlf_loader_and_native_shap(tmp_path):
    from services.url_detector import URLDetector, MODEL_PATH, extract_features
    artifact = tmp_path / 'model-crlf.txt'
    artifact.write_bytes(Path(MODEL_PATH).read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    detector = URLDetector(str(artifact))
    assert detector.model is not None and detector.explainer is not None
    features = extract_features('http://verify-paypal-account.xyz/login').reshape(1, -1)
    contributions = detector.model.predict(features, pred_contrib=True, num_threads=1)
    raw = detector.model.predict(features, raw_score=True, num_threads=1)
    np.testing.assert_allclose(contributions.sum(axis=1), raw, rtol=1e-5)
    np.testing.assert_allclose(detector.explainer.shap_values(features), contributions[:, :-1])
