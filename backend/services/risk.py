"""Evidence-based online policy; the browser consumes the should_block result."""
import math
import re
import ipaddress
from urllib.parse import urlsplit

WEIGHTS = {'url': 30, 'nlp': 40, 'dom': 30}
POLICY_VERSION = 'evidence-v2'
BLOCK_THRESHOLD = 50  # Preserve the existing precautionary URL threshold.


def risk_level(score, degraded=False):
    if score is None or (degraded and score <= 30):
        return 'unknown'
    return 'safe' if score <= 30 else 'suspicious' if score <= 70 else 'dangerous'


def hard_url_indicators(url):
    host = (urlsplit(url).hostname or '').lower()
    flags = []
    try:
        ipaddress.ip_address(host)
        flags.append('ip_host')
    except ValueError:
        pass
    if '@' in urlsplit(url).netloc: flags.append('userinfo')
    if any(label.startswith('xn--') for label in host.split('.')): flags.append('idn')
    if host.rsplit('.', 1)[-1] in {'xyz','tk','ml','ga','cf','gq','top','work','click','buzz','link'}: flags.append('high_risk_tld')
    if re.search(r'paypa[1i]|micros[0o]ft-(?:login|signin)|amaz[0o]n-prime|g[0o]{2}gle-account', host): flags.append('brand_lookalike')
    return flags


def urgent_lure(text):
    text = text.lower()
    # Require both a direct action and an account threat/deadline, not a lone keyword.
    if re.search(r'educational|phishing (?:attack|works)|scammers|never enter|do not follow', text):
        return False
    return bool(re.search(r'verify (?:your )?account|confirm your identity|enter your password', text) and
                re.search(r'account (?:has been |will be )?(?:suspended|closed)|within (?:24|48) hours|unusual sign.in', text))


def should_block(scores, final, evidence):
    return bool((final or 0) > 70 and (scores.get('nlp') is not None or scores.get('dom') is not None or evidence.get('hard_url')) or
                evidence.get('hard_url') and (scores.get('url') or 0) >= BLOCK_THRESHOLD)


def combine(scores, evidence=None):
    available = {k: v for k, v in scores.items() if v is not None}
    if not available:
        return None
    if any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) or not 0 <= v <= 100 for v in available.values()):
        raise ValueError('Detector returned invalid score')
    # Integer weights avoid float artifacts; integer truncation retains the original policy.
    score = int(sum(WEIGHTS[k] * v for k, v in available.items()) / sum(WEIGHTS[k] for k in available))
    if evidence is not None:
        url, nlp, dom = scores.get('url'), scores.get('nlp'), scores.get('dom')
        # The current URL artifact is overconfident. Preserve its reported score,
        # but bound its vote when full-page evidence does not corroborate it.
        if nlp is not None and dom is not None and not evidence.get('hard_url') and dom < 40:
            score = int((30 * min(url or 0, 30) + 40 * nlp + 30 * dom) / 100)
        if dom is not None and dom >= 80 and ((nlp or 0) >= 50 or evidence.get('brand_credential')):
            score = max(score, 90)
        if (nlp or 0) >= 75 and evidence.get('urgent_lure'):
            score = max(score, 75)
        if evidence.get('hard_url') and (url or 0) >= 90:
            score = max(score, 90)
    return score
