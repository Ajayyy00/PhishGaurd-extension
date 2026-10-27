"""Regressions for the October 27 audit; real trained artifacts, no model mocks."""
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from services.risk import combine, should_block, hard_url_indicators, urgent_lure
from services.dom_detector import DOMDetector
from services.url_detector import get_detector, FEATURE_NAMES
from services.nlp_detector import get_nlp_detector
from feature_engine import extract_features, extract_features_batch


def test_feature_schema_and_batch_inference_parity():
    urls = ['https://www.google.com/', 'https://www.cloudflare.com/', 'http://192.0.2.15:8088/a',
            'https://example.org/oauth?client_id=a&state=b', 'https://localhost:443/']
    assert get_detector().model.feature_name() == FEATURE_NAMES
    np.testing.assert_allclose(extract_features_batch(pd.Series(urls)), np.stack([extract_features(u) for u in urls]))
    # The old NaN port bug cannot explain saturation: the saved model never splits on this column.
    assert get_detector().model.feature_importance()[FEATURE_NAMES.index('has_port')] == 0


@pytest.mark.parametrize('url', ['https://untrusted.org/login', 'https://untrusted.net/auth?client_id=a&redirect_uri=b&state=c', 'https://unverified.github.com/login'])
def test_attacker_controlled_url_properties_do_not_discount(url):
    assert get_detector()._apply_heuristic_adjustments(url, 80) == 80


@pytest.mark.parametrize('url', ['https://members.example.org/login', 'https://github.com/login', 'https://accounts.example.org/sign-in'])
def test_generic_same_site_login_is_not_brand_impersonation(url):
    d = DOMDetector().analyze_dom({'title': 'Member sign in', 'inputs': [{'type': 'email'}, {'type': 'password'}], 'forms': [{'action': '/session'}]}, url)
    assert d['score'] <= 45 and not d['is_domain_mismatch']


@pytest.mark.parametrize('brand', ['PayPal', 'Microsoft', 'Apple', 'Google', 'Amazon'])
def test_claimed_brand_with_credentials_on_untrusted_host(brand):
    d = DOMDetector().analyze_dom({'title': brand, 'inputs': [{'type': 'password'}], 'forms': [{'action': '/session'}]}, 'https://untrusted.example.org/login')
    assert d['score'] >= 80 and d['fingerprint']['brand_impersonation']


def test_seed_surface_and_external_credential_form():
    d = DOMDetector()
    assert d.analyze_dom({'inputs': [{'tag': 'textarea', 'label': '12 word recovery phrase'}]}, 'https://example.org')['score'] >= 80
    assert d.analyze_dom({'inputs': [{'type': 'password'}], 'forms': [{'action': 'https://collector.invalid'}]}, 'https://example.org')['score'] >= 80


def test_social_signin_button_is_not_primary_brand_claim():
    d = DOMDetector().analyze_dom({'title': 'Sign in to GitHub', 'headings': 'Sign in to GitHub',
        'visibleText': 'Sign in with Google. Sign in with Apple. Enter your password.',
        'inputs': [{'type': 'password'}], 'forms': [{'action': '/session'}]}, 'https://github.com/login')
    assert d['score'] <= 45 and not d['is_domain_mismatch']


def test_account_recovery_code_is_not_wallet_seed():
    d = DOMDetector().analyze_dom({'title': 'Recover account', 'inputs': [{'type': 'text', 'name': 'recovery_code', 'label': 'Account recovery code'}]}, 'https://example.org')
    assert not d['fingerprint']['seed_phrase'] and d['score'] < 80


def test_brand_claim_in_credential_label():
    d = DOMDetector().analyze_dom({'title': 'Account', 'inputs': [{'type': 'password', 'label': 'Your PayPal password'}],
                                  'forms': [{'action': '/session'}]}, 'https://untrusted.example.org')
    assert d['fingerprint']['brand_impersonation'] and d['score'] >= 80


def test_real_transformer_preserves_late_lure_and_seed_risk():
    detector = get_nlp_detector()
    for text in [('Community gardening and books. ' * 400) + ' Urgent! Verify your account. Enter your password immediately.',
                 'Restore your wallet now. Enter your 12 word recovery seed phrase to validate your wallet. Your funds are at risk.']:
        value = detector.predict_risk(text)
        assert value['model_used'] and value['transformer_probability'] >= .85 and value['score'] >= 75
    assert detector.predict_risk(('Community gardening and books. ' * 400) + ' Verify your account immediately.')['windows_evaluated'] == 2


def test_evidence_policy_false_positive_and_false_negative_regressions():
    benign = {'url': 99, 'nlp': 20, 'dom': 0}
    evidence = {'hard_url': []}
    score = combine(benign, evidence)
    assert score < 45 and not should_block(benign, score, evidence)
    clone = {'url': 10, 'nlp': 75, 'dom': 90}
    score = combine(clone, evidence)
    assert score > 70 and should_block(clone, score, evidence)
    partial = {'url': 10, 'nlp': None, 'dom': 90}
    partial_evidence = {'hard_url': [], 'brand_credential': True}
    assert should_block(partial, combine(partial, partial_evidence), partial_evidence)
    url_only = {'url': 99, 'nlp': None, 'dom': None}
    assert not should_block(url_only, 99, evidence)
    assert should_block(url_only, 99, {'hard_url': hard_url_indicators('http://192.0.2.10/login')})
    assert urgent_lure('Your account has been suspended. Confirm your identity within 24 hours.')
    assert not urgent_lure('Scammers say your account will be closed. Never enter your password.')
