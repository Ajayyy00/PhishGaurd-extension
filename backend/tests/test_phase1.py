import math
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from services.risk import combine, risk_level
from services.cache import TTLCache
from services.dom_detector import DOMDetector
from services.nlp_detector import NLPDetector
from utils.validators import validate_analyze_request, validate_batch_request
from utils.security import RateLimit


@pytest.mark.parametrize('score,expected', [(0,'safe'),(30,'safe'),(31,'suspicious'),(70,'suspicious'),(71,'dangerous'),(100,'dangerous'),(None,'unknown')])
def test_boundaries(score, expected):
    assert risk_level(score) == expected
    assert risk_level(0, True) == 'unknown'


@pytest.mark.parametrize('scores,expected', [({'url':20},20),({'url':20,'nlp':60},42),({'url':20,'dom':80},50),({'url':20,'nlp':60,'dom':80},54),({'url':90,'nlp':0,'dom':0},90),({'url':None},None)])
def test_weights(scores, expected):
    assert combine(scores) == expected


@pytest.mark.parametrize('score', [True,-1,101,float('nan'),float('inf'),'20'])
def test_bad_scores(score):
    with pytest.raises(ValueError): combine({'url':score})


def test_cache_expiry_lru_copy_and_concurrency():
    now = [0]
    cache = TTLCache(2, 10, lambda: now[0])
    cache.put('a', {'x':[1]}); cache.put('b', {})
    value = cache.get('a'); value['x'].append(2)
    cache.put('c', {})
    assert cache.get('b') is None and cache.get('a') == {'x':[1]}
    assert cache.stats()['evictions'] == 1
    now[0] = 10
    assert cache.get('a') is None and cache.stats()['size'] == 0
    def access(i):
        cache.put(i, {'value':i}); cache.get(i); cache.stats()
    with ThreadPoolExecutor(8) as pool: list(pool.map(access, range(100)))
    assert cache.stats()['size'] <= 2


@pytest.mark.parametrize('data', [None,[],{}, {'url':2},{'url':'javascript:alert(1)'},{'url':'https://'},{'url':'http://a:99999'}, {'url':'https://a b'}, {'url':'https://a/\n'}, {'url':'https://a\\b'}, {'url':'https://a/'+'x'*2048},{'url':'https://a','text':None},{'url':'https://a','text':'x'*100001},{'url':'https://a','dom':[]},{'url':'https://a','dom':{'stats':{'forms':True}}},{'url':'https://a','dom':{'inputs':[None]}},{'url':'https://a','dom':{'title':False}},{'url':'https://a','dom':{'visibleText':'x'*65536}},{'url':'https://a','force_refresh':1}])
def test_invalid_requests(data):
    assert validate_analyze_request(data)


@pytest.mark.parametrize('url', ['https://example.com/','http://localhost:8765/','https://例え.jp/道?q=%3Csvg%3E','https://[::1]/'])
def test_valid_urls(url):
    assert validate_analyze_request({'url':url, 'text':'', 'dom':{}}) is None


def test_batch_validation():
    for data in [[],{}, {'urls':[]},{'urls':['file:///a']},{'urls':[3]},{'urls':['https://a']*101}]:
        assert validate_batch_request(data)
    assert validate_batch_request({'urls':['https://a','https://b']}) is None


def test_stage_cache_and_refresh(service):
    url = 'https://example.com'
    first = service.analyze(url)
    assert first['final_score'] == 20 and first['nlp_risk'] is None
    assert first['detectors']['nlp']['status'] == 'not_run'
    assert service.analyze(url)['cached']
    text = 'A sufficiently long input for the text detector.'
    full = service.analyze(url, text, {'stats':{'forms':1}})
    assert full['analysis_stage'] == 'full' and full['final_score'] == 54
    assert not full['cached']
    assert not service.analyze(url, force_refresh=True)['cached']
    assert not service.analyze(url, text+'changed', {'stats':{'forms':1}})['cached']


def test_failure_not_safe_and_recovery(service, monkeypatch):
    def fail(*args): raise RuntimeError('private details')
    monkeypatch.setattr(service, '_analyze_url', fail)
    result = service.analyze('https://example.com')
    assert result['degraded'] and result['risk_level'] == 'unknown'
    assert result['detectors']['url']['source'] == 'heuristic_fallback'
    assert 'private details' not in str(result)
    monkeypatch.setattr(service, '_analyze_url', lambda u: {'risk':0})
    assert service.analyze('https://example.com')['risk_level'] == 'safe'
    monkeypatch.setattr(service, '_analyze_text', fail)
    result = service.analyze('https://example.com','sufficiently long text to invoke NLP')
    assert result['nlp_risk'] is None and result['detectors']['nlp']['status'] == 'failed'


def test_timeout(service, monkeypatch):
    service.timeout = .01
    monkeypatch.setattr(service, '_analyze_text', lambda t: (time.sleep(.05), {'risk':1})[1])
    result = service.analyze('https://example.com','a sufficiently long timeout input')
    assert result['detectors']['nlp']['status'] == 'timed_out'
    assert result['nlp_risk'] is None
    time.sleep(.06)


def test_missing_models_and_preprocessing(monkeypatch):
    monkeypatch.setattr(NLPDetector, '_load_model', lambda self: None)
    detector = NLPDetector()
    result = detector.predict_risk('Urgent: verify your account and enter your password immediately.')
    assert result['score'] is None and not result['model_used']
    assert 'urgent' in result['suspicious_phrases']
    assert detector.preprocess_text('HI! a@b.com https://example.com  FRIEND') == 'hi friend'
    from services.url_detector import URLDetector
    detector = URLDetector('missing-test-artifact')
    with pytest.raises(RuntimeError): detector.predict_url_risk('https://example.com', strict=True)


def test_dom_exact_host_and_forms():
    detector = DOMDetector()
    dom = {'title':'PayPal','stats':{'forms':1,'inputs':3},'inputs':[{'type':'password'},{'type':'email'}],'forms':[{'action':'https://paypal.com/login'}]}
    assert not detector.analyze_dom(dom,'https://paypal.com/login')['is_domain_mismatch']
    assert not detector.analyze_dom(dom,'https://secure.paypal.com/login')['is_domain_mismatch']
    fake = detector.analyze_dom(dom,'https://paypal.com.evil.test/login')
    assert fake['is_domain_mismatch'] and fake['score'] >= 70
    assert not detector.analyze_dom({'title':'Happy community'},'https://example.com')['fingerprint']['detected_brand']
    assert not detector._generate_fingerprint(dom,'https://paypal.com/login')['suspicious_form_action']


def test_auth_cors_and_host(app, client):
    assert app.test_client().get('/api/status').status_code == 401
    assert app.test_client().get('/health').status_code == 200
    assert client.get('/api/info').status_code == 200
    assert client.get('/api/status', headers={'Origin':'https://evil.example'}).status_code == 403
    assert client.get('/api/status', headers={'Host':'evil.example'}).status_code == 403
    assert client.get('/api/status', headers={'Host':'[2001:db8::1]'}).status_code == 403
    origin = app.config['EXTENSION_ORIGINS'][0]
    response = client.get('/api/status', headers={'Origin':origin})
    assert response.headers['Access-Control-Allow-Origin'] == origin
    assert app.test_client().get('/api/status', headers={'Origin':origin}).status_code == 401
    response = app.test_client().options('/api/analyze', headers={'Origin':origin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Authorization,Content-Type'})
    assert response.status_code == 204
    assert client.options('/api/analyze', headers={'Origin':'https://evil.example','Access-Control-Request-Method':'POST'}).status_code == 403
    assert 'Access-Control-Allow-Origin' not in client.get('/health').headers


def test_api_limits_errors_recovery(app, client, service, monkeypatch):
    app.extensions['analyzer'] = service
    for data in [None,[],{}, {'url':'file:///x'},{'url':'https://a','dom':{'inputs':[1]}}]:
        assert client.post('/api/analyze', json=data).status_code == 400
    assert client.post('/api/analyze', data='{', content_type='application/json').status_code == 400
    assert client.post('/api/analyze', data='x'*262145,content_type='application/json').status_code == 413
    assert client.post('/api/analyze', json={'url':'https://a'}).json['analysis_stage'] == 'url_only'
    original = service.analyze
    def sometimes(url, **kw):
        if 'fail' in url: raise RuntimeError('sensitive-test-data')
        return original(url, **kw)
    monkeypatch.setattr(service,'analyze',sometimes)
    response = client.post('/api/batch', json={'urls':['https://fail.test','https://a']})
    assert response.status_code == 200
    assert response.json['results'][0]['final_score'] is None
    assert response.json['results'][1]['final_score'] == 20
    assert 'sensitive-test-data' not in response.text
    app.extensions['rate_limit'].limit = 1
    assert client.post('/api/analyze',json={'url':'https://a'}).status_code == 429
    app.extensions['rate_limit'].events.clear()
    assert client.post('/api/batch',json={'urls':['https://a','https://b']}).status_code == 429


def test_limiter_expiration():
    now = [0]; limit = RateLimit(2,60,lambda:now[0])
    assert limit.allow(2) and not limit.allow()
    now[0] = 60
    assert limit.allow()


def test_saturated_pool_and_invalid_detector(service, monkeypatch):
    import services.analyzer as module
    monkeypatch.setattr(module, 'submit_detection', lambda *args: None)
    result = service.analyze('https://example.com')
    assert result['degraded'] and result['detectors']['url']['status'] == 'failed'
    assert result['risk_level'] == 'unknown' and not result['cached']


def test_dom_and_nan_failure_are_not_zero(service, monkeypatch):
    monkeypatch.setattr(service, '_analyze_dom', lambda *args: {'risk':float('nan')})
    result = service.analyze('https://example.com',dom={'title':'Test'})
    assert result['dom_risk'] is None and result['final_score'] == 20
    assert result['degraded'] and result['detectors']['dom']['status'] == 'failed'


def test_singleton_initialization_is_serial(monkeypatch):
    import services.dom_detector as module
    count = []
    class Detector:
        def __init__(self):
            time.sleep(.005); count.append(1)
    monkeypatch.setattr(module, '_dom_detector_instance', None)
    monkeypatch.setattr(module, 'DOMDetector', Detector)
    with ThreadPoolExecutor(8) as pool: values = list(pool.map(lambda _:module.get_dom_detector(),range(20)))
    assert len(count) == 1 and len({id(v) for v in values}) == 1


@pytest.mark.parametrize('url,expected', [('https://example.com/',0),('http://localhost/',20),('http://127.0.0.1/login',70),('http://verify-paypal-account.xyz/login',85),('https://user@host.test/',40)])
def test_shared_fallback_policy(url,expected):
    from services.url_detector import URLDetector
    assert URLDetector._basic_heuristic_score(None,url) == expected
