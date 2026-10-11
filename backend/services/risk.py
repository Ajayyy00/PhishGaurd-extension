"""Canonical v1 risk policy, mirrored by extension/shared/risk.js."""
import math

WEIGHTS = {'url': 30, 'nlp': 40, 'dom': 30}
POLICY_VERSION = 'phase1-v1'
BLOCK_THRESHOLD = 50  # Preserve the existing precautionary URL threshold.


def risk_level(score, degraded=False):
    if score is None or (degraded and score <= 30):
        return 'unknown'
    return 'safe' if score <= 30 else 'suspicious' if score <= 70 else 'dangerous'


def combine(scores):
    available = {k: v for k, v in scores.items() if v is not None}
    if not available:
        return None
    if any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) or not 0 <= v <= 100 for v in available.values()):
        raise ValueError('Detector returned invalid score')
    # Integer weights avoid float artifacts; integer truncation retains the original policy.
    score = int(sum(WEIGHTS[k] * v for k, v in available.items()) / sum(WEIGHTS[k] for k in available))
    if (scores.get('url') or 0) >= 90:
        score = max(score, 90)
    return score
