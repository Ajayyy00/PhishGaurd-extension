"""Real-model verification against default checkout paths; no model overrides."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).parent / 'artifacts'
OUT.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / 'backend'))
os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',
                  PYTHONDONTWRITEBYTECODE='1', FLASK_ENV='production')
TOKEN = secrets.token_urlsafe(32)
os.environ['PHISHGUARD_API_TOKEN'] = TOKEN
TEXT = 'Urgent! Verify your account immediately. Your account will be closed within 24 hours. Enter your password. Confirm your identity.'
DOM = {'title': 'PayPal account verification', 'visibleText': TEXT,
       'stats': {'forms': 1, 'inputs': 3, 'links': 0},
       'forms': [{'action': 'https://collector.test/submit'}],
       'inputs': [{'type': 'email'}, {'type': 'password'}, {'type': 'text', 'name': 'username'}]}


def probe(mode):
    if mode == 'url':
        from services.url_detector import URLDetector, extract_features
        detector = URLDetector()
        assert detector.model is not None and detector.explainer is not None
        assert len(extract_features('https://example.com')) == 22
        score = detector.predict('http://verify-paypal-account.xyz/login')
        explanations = detector.explain_prediction('http://verify-paypal-account.xyz/login')
        assert 0 <= score <= 100 and explanations
        return {'model_loaded': True, 'shap_loaded': True, 'score': score, 'explanations': explanations}
    if mode == 'nlp':
        from services.nlp_detector import NLPDetector
        detector = NLPDetector()
        assert detector.model is not None and detector.tokenizer is not None
        result = detector.predict_risk(TEXT)
        assert result['score'] > 0 and result['suspicious_phrases']
        return {'model_loaded': True, 'tokenizer_loaded': True, 'result': result}
    if mode == 'dom':
        from services.dom_detector import DOMDetector
        detector = DOMDetector()
        result = detector.analyze_dom(DOM, 'http://verify-paypal-account.xyz/login')
        assert result['score'] > 0 and result['matched_template'] == 'paypal'
        assert detector.analyze_dom({}, 'https://example.com')['score'] == 0
        return result
    if mode == 'full_app':
        from app import create_app
        app = create_app('testing')
        output = {}
        with app.test_client() as client:
            headers = {'Authorization': 'Bearer ' + TOKEN}
            for endpoint in ('/health', '/api/status', '/api/info'):
                response = client.get(endpoint, headers=headers)
                assert response.status_code == 200
                output[endpoint] = response.get_json()
            assert output['/api/status']['model_loaded'] is True
            assert client.post('/api/analyze', json={'url': 'https://example.com'}).status_code == 401
            response = client.post('/api/analyze', headers=headers, json={
                'url': 'http://verify-paypal-account.xyz/login', 'text': TEXT, 'dom': DOM})
            assert response.status_code == 200
            result = response.get_json()
            assert result['analysis_stage'] == 'full' and not result['degraded']
            assert all(result[key] > 0 for key in ('url_risk', 'nlp_risk', 'dom_risk'))
            assert result['risk_score'] == result['final_score']
            assert result['reasons'] == [item['message'] for item in result['explanations']]
            output['analysis'] = result
        return output
    if mode == 'cache':
        # Use the same default factory as run.py so cold-start model loading is included.
        from app import create_app
        analyzer = create_app('testing').extensions['analyzer']
        url = 'https://example.org/cache-check'
        first = analyzer.analyze(url)
        full = analyzer.analyze(url, text=TEXT, dom=DOM)
        cached = analyzer.analyze(url, text=TEXT, dom=DOM)
        refreshed = analyzer.analyze(url, text=TEXT, dom=DOM, force_refresh=True)
        assert first['final_score'] == first['url_risk']
        assert first['nlp_risk'] is None and first['dom_risk'] is None
        assert first['analysis_stage'] == 'url_only' and full['analysis_stage'] == 'full'
        assert full['nlp_risk'] > 0 and full['dom_risk'] > 0 and not full['cached']
        assert cached['cached'] is True and refreshed['cached'] is False
        return {'url_only': first, 'full': full, 'cached': cached, 'refreshed': refreshed}
    raise ValueError(mode)


if len(sys.argv) > 1:
    result = probe(sys.argv[1])
    (OUT / (sys.argv[1] + '.json')).write_text(json.dumps(result, indent=2), encoding='utf-8')
else:
    outcomes = {}
    for mode in ('url', 'nlp', 'dom', 'full_app', 'cache'):
        start = time.monotonic()
        with (OUT / (mode + '.log')).open('w', encoding='utf-8') as log:
            try:
                process = subprocess.run([sys.executable, '-X', 'utf8', '-u', __file__, mode],
                    cwd=OUT, env=os.environ, stdout=log, stderr=log, timeout=120)
                outcomes[mode] = {'status': 'VERIFIED' if process.returncode == 0 else 'FAILED',
                                  'exit_code': process.returncode, 'seconds': round(time.monotonic()-start, 2)}
            except subprocess.TimeoutExpired:
                outcomes[mode] = {'status': 'FAILED', 'timeout_seconds': 120}
        print(mode, outcomes[mode], flush=True)
        (OUT / 'model-probe-summary.json').write_text(json.dumps(outcomes, indent=2), encoding='utf-8')
    sys.exit(0 if all(r['status'] == 'VERIFIED' for r in outcomes.values()) else 1)
