"""
PhishGuard URL Detector
ML-based URL risk detection using LightGBM and production feature engine.
"""

import re
import os
import sys
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

import numpy as np
import lightgbm as lgb

# Add models/training to path so we can import feature_engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'training'))
from feature_engine import extract_features, FEATURE_NAMES


# Model storage path — LightGBM native text format
MODEL_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', 'models', 'saved', 'lgbm_url_model.txt'
)


class URLDetector:
    """
    URL-based phishing detection using LightGBM.
    Extracts 22 features from URLs and predicts risk scores.
    """

    def __init__(self, model_path: str = MODEL_PATH):
        """Initialize detector with pre-trained LightGBM model."""
        self.model = None
        self.explainer = None
        self.model_path = model_path
        self.feature_names = FEATURE_NAMES
        self._load_model()

    def _load_model(self):
        """Load the LightGBM model from disk."""
        try:
            if os.path.exists(self.model_path):
                self.model = lgb.Booster(model_file=self.model_path)
                print(f"Loaded LightGBM URL model from {self.model_path}")

                # Initialize SHAP explainer
                try:
                    import shap
                    self.explainer = shap.TreeExplainer(self.model)
                    print("SHAP TreeExplainer initialized for LightGBM URL model")
                except Exception as e:
                    print(f"Could not initialize SHAP explainer: {e}")
            else:
                print(f"LightGBM model not found at {self.model_path}")
        except Exception as e:
            print(f"Error loading LightGBM model: {e}")

    def predict(self, url: str) -> float:
        """Predict phishing probability for a URL (0-100)."""
        if not self.model:
            return 50.0  # Default if model missing

        features = extract_features(url)
        try:
            # LightGBM Booster.predict() returns probabilities directly
            features_reshaped = features.reshape(1, -1)
            prob = self.model.predict(features_reshaped)[0]
            risk_score = prob * 100

            # --- Anti-False-Positive Heuristics ---
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            query = (parsed.query or '').lower()
            path = (parsed.path or '').lower()

            # 1. Safe Academic/Gov/Org TLDs
            safe_tlds = ('.edu', '.ac.in', '.gov', '.mil', '.edu.in', '.ac.uk', '.org')
            if hostname.endswith(safe_tlds):
                risk_score *= 0.5  # Reduce risk by half

            # 2. OAuth / SSO Patterns
            oauth_params = ['client_id=', 'redirect_uri=', 'response_type=', 'state=', 'nonce=', 'oauth']
            oauth_matches = sum(1 for param in oauth_params if param in query or param in path)
            if oauth_matches >= 2:
                risk_score *= 0.4  # Reduce risk significantly

            return round(risk_score, 2)
        except Exception as e:
            print(f"Prediction error: {e}")
            return 50.0

    def explain_prediction(self, url: str) -> List[Dict[str, Any]]:
        """
        Explain why a URL was predicted as phishing using SHAP.
        Returns top 5 contributing features.
        """
        if not self.model or not self.explainer:
            return []

        # Don't explain danger if final heuristic score is safe
        if self.predict(url) < 40:
            return []

        try:
            features = extract_features(url)
            features_reshaped = features.reshape(1, -1)

            # Calculate SHAP values
            shap_values = self.explainer.shap_values(features_reshaped)

            # Handle different SHAP output formats
            if isinstance(shap_values, list):
                vals = shap_values[1][0]
            else:
                vals = shap_values[0]

            # Create (feature, shap_value) pairs
            feature_contributions = []
            for name, val in zip(self.feature_names, vals):
                if val > 0:  # Only features increasing risk
                    feature_contributions.append({
                        'feature': self._get_readable_feature_name(name, url),
                        'impact': float(val),
                        'raw_feature': name
                    })

            # Sort by impact (descending) and take top 5
            feature_contributions.sort(key=lambda x: x['impact'], reverse=True)
            return feature_contributions[:5]

        except Exception as e:
            print(f"Explanation error: {e}")
            return []

    def _get_readable_feature_name(self, feature: str, url: str) -> str:
        """Convert feature name to human-readable explanation."""
        mapping = {
            'url_length': 'Unusually long URL',
            'domain_length': 'Long domain name',
            'path_length': 'Deep URL path',
            'query_length': 'Long query string',
            'fragment_length': 'URL fragment present',
            'num_dots': 'Many dots in URL',
            'num_hyphens': 'Many hyphens in URL',
            'num_underscores': 'Many underscores in URL',
            'num_slashes': 'Many path segments',
            'num_digits': 'High number of digits',
            'num_params': 'Many URL parameters',
            'num_at_symbols': 'Contains "@" symbol (obscured destination)',
            'num_eq_signs': 'Many equals signs',
            'num_ampersands': 'Many ampersands',
            'has_ip_address': 'Uses raw IP address instead of domain',
            'has_https': 'Lack of secure HTTPS connection',
            'has_port': 'Uses non-standard port',
            'entropy': 'Random-looking URL characters',
            'digit_ratio': 'High ratio of digits',
            'special_char_ratio': 'High ratio of special characters',
            'subdomain_depth': 'Multiple subdomains',
            'path_depth': 'Deep URL path structure',
        }
        return mapping.get(feature, feature.replace('_', ' ').capitalize())

    def predict_url_risk(self, url: str) -> int:
        """
        Predict phishing risk score for a URL.

        Args:
            url: The URL to analyze

        Returns:
            Risk score from 0-100
        """
        if not self.model:
            self._load_model()

        if not url:
            return 0

        # Skip chrome:// and similar
        if url.startswith(('chrome://', 'chrome-extension://', 'about:', 'file://')):
            return 0

        try:
            # Extract features using production feature engine
            features = extract_features(url).reshape(1, -1)

            # LightGBM predict returns probability directly
            phishing_prob = self.model.predict(features)[0]

            # Convert to 0-100 score
            score = int(phishing_prob * 100)

            # Add heuristic adjustments for edge cases
            score = self._apply_heuristic_adjustments(url, score)

            return max(0, min(100, score))

        except Exception as e:
            # Fallback to basic heuristic
            return self._basic_heuristic_score(url)

    def _apply_heuristic_adjustments(self, url: str, score: int) -> int:
        """Apply additional heuristic adjustments to ML score."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            query = (parsed.query or '').lower()
            path = (parsed.path or '').lower()

            # Known safe domains — hard cap (LightGBM scores many real domains high)
            if self._is_legitimate_brand_domain(hostname):
                score = min(score, 10)

            # 1. Safe Academic/Gov/Org TLDs
            safe_tlds = ('.edu', '.ac.in', '.gov', '.mil', '.edu.in', '.ac.uk', '.org')
            if hostname.endswith(safe_tlds):
                score = int(score * 0.5)

            # 2. OAuth / SSO Patterns
            oauth_params = ['client_id=', 'redirect_uri=', 'response_type=', 'state=', 'nonce=', 'oauth']
            oauth_matches = sum(1 for param in oauth_params if param in query or param in path)
            if oauth_matches >= 2:
                score = int(score * 0.4)

            # IP addresses are very suspicious
            if self._is_ip_address(hostname):
                score = min(100, score + 30)

            # @ symbol is highly suspicious
            if '@' in url:
                score = min(100, score + 40)

            # Suspicious TLDs - boost score significantly
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.buzz', '.link']
            if any(hostname.endswith(tld) for tld in suspicious_tlds):
                score = min(100, score + 35)

            # HTTP (not HTTPS) is risky
            if parsed.scheme == 'http':
                score = min(100, score + 15)

        except Exception:
            pass

        return score

    def _basic_heuristic_score(self, url: str) -> int:
        """Fallback heuristic scoring when ML fails."""
        score = 0

        if not url.startswith('https://'):
            score += 15
        if '@' in url:
            score += 30
        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 30
        if len(url) > 100:
            score += 10
        if url.count('.') > 5:
            score += 10

        return min(100, score)

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, hostname or ''))

    def _is_legitimate_brand_domain(self, hostname: str) -> bool:
        """Check if hostname is a legitimate brand domain."""
        legit_domains = {
            # Tech Giants
            'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 'instagram.com',
            # AI Services
            'chatgpt.com', 'openai.com', 'anthropic.com', 'claude.ai',
            # Dev Tools
            'github.com', 'gitlab.com', 'stackoverflow.com', 'vercel.com',
            # Finance
            'paypal.com', 'stripe.com', 'ebay.com',
            # Entertainment
            'netflix.com', 'spotify.com', 'twitch.tv', 'discord.com',
            # Other
            'reddit.com', 'wikipedia.org', 'medium.com', 'notion.so',
            'dropbox.com', 'zoom.us', 'slack.com'
        }

        for domain in legit_domains:
            if hostname == domain or hostname.endswith('.' + domain):
                return True
        return False

    def get_feature_importance(self) -> List[Tuple[str, float]]:
        """Get feature importance from trained model."""
        if not self.model:
            return []

        try:
            importances = self.model.feature_importance(importance_type='gain')
            return sorted(
                zip(self.feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )
        except Exception:
            return []


# Singleton instance for reuse
_detector_instance = None


def get_detector() -> URLDetector:
    """Get or create singleton detector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = URLDetector()
    return _detector_instance


def predict_url_risk(url: str) -> int:
    """
    Convenience function to predict URL risk.

    Args:
        url: URL to analyze

    Returns:
        Risk score 0-100
    """
    return get_detector().predict_url_risk(url)


def train_model() -> Dict[str, Any]:
    """
    Placeholder for backward compatibility.
    Training is now handled by models/training/train_lgbm.py.

    Returns:
        Info message
    """
    return {
        'message': 'Training is handled by models/training/train_lgbm.py',
        'model_path': MODEL_PATH,
    }
