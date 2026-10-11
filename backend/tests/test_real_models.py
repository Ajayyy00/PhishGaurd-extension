"""Separate saved-artifact integration tests; no detector mocks."""
import json
from pathlib import Path
import numpy as np
import pytest

pytestmark = pytest.mark.real_model


def test_saved_models_and_full_pipeline(app, client):
    from services.url_detector import get_detector, extract_features, FEATURE_NAMES
    from services.nlp_detector import get_nlp_detector
    from services.risk import combine
    url_detector = get_detector()
    assert url_detector.model is not None
    assert url_detector.model.feature_name() == FEATURE_NAMES
    features = extract_features('https://example.com/a?q=1')
    assert features.shape == (22,) and np.isfinite(features).all()
    assert features[0] == 25 and features[15] == 1
    # Native TreeSHAP additivity checks the actual explanation engine.
    raw = url_detector.model.predict(features.reshape(1,-1), raw_score=True,num_threads=1)[0]
    contributions = url_detector.model.predict(features.reshape(1,-1),pred_contrib=True,num_threads=1)[0]
    assert float(contributions.sum()) == pytest.approx(float(raw), abs=1e-5)
    assert url_detector.explain_prediction('http://verify-paypal-account.xyz/login')
    nlp = get_nlp_detector()
    assert nlp.model is not None and nlp.tokenizer is not None
    text = 'Urgent! Verify your account immediately. Enter your password. Your account will be closed within 24 hours.'
    prediction = nlp.predict_risk(text)
    assert prediction['model_used'] and 0 <= prediction['score'] <= 100
    assert 'urgent' in prediction['suspicious_phrases']
    dom = {'title':'PayPal','stats':{'forms':1,'inputs':3},'inputs':[{'type':'password'},{'type':'email'}],'forms':[{'action':'http://verify-paypal-account.xyz/login'}]}
    results = []
    for url in ['http://localhost:8765/benign','http://fixture.github.com:8765/benign','http://verify-paypal-account.xyz:8765/login']:
        body = {'url':url,'text':text,'dom':dom}
        response = client.post('/api/analyze',json=body)
        assert response.status_code == 200
        result = response.json
        assert all(v['status'] == 'ok' for v in result['detectors'].values())
        assert result['analysis_stage'] == 'full' and not result['degraded']
        assert result['final_score'] == combine(result['breakdown'])
        assert result['explanations'] and not result['errors']
        results.append(result)
    assert client.post('/api/analyze',json=body).json['cached']
    assert client.get('/api/status').json['model_loaded']
    path = Path(__file__).resolve().parents[2] / 'tests/e2e/artifacts/real-model-results.json'
    path.write_text(json.dumps({'models': {'url':'LightGBM','nlp':nlp.model.config.to_dict().get('_name_or_path')},'results':results},indent=2),encoding='utf-8')
