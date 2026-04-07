"""
PhishGuard LightGBM Inference Module
Ultra-fast single-URL prediction using the native LightGBM .txt model.

Target latency: <2ms per prediction (model load cached via module-level singleton).
"""

import os
import time
from typing import Dict, Optional, Tuple

import lightgbm as lgb
import numpy as np

from feature_engine import extract_features


# ============================================================================
# Configuration
# ============================================================================

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "saved", "lgbm_url_model.txt"
)

# Module-level model cache (singleton pattern — load once, predict forever)
_model_cache: Dict[str, lgb.Booster] = {}


# ============================================================================
# Model Loading (cached)
# ============================================================================

def _load_model(model_path: str) -> lgb.Booster:
    """
    Load a LightGBM Booster from a native .txt file.
    Caches the model object to avoid repeated disk I/O.

    Args:
        model_path: Absolute path to the .txt model file.

    Returns:
        LightGBM Booster instance.

    Raises:
        FileNotFoundError: If the model file does not exist.
    """
    if model_path in _model_cache:
        return _model_cache[model_path]

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at: {model_path}. "
            f"Run train_lgbm.py first to train and export the model."
        )

    booster = lgb.Booster(model_file=model_path)
    _model_cache[model_path] = booster
    return booster


# ============================================================================
# Prediction API
# ============================================================================

def predict_url(
    url: str,
    model_path: str = DEFAULT_MODEL_PATH,
    threshold: float = 0.5,
) -> Dict[str, object]:
    """
    Predict whether a URL is benign or malicious.

    Args:
        url:        Raw URL string to classify.
        model_path: Path to the trained LightGBM .txt model.
        threshold:  Classification threshold (default: 0.5).

    Returns:
        Dictionary containing:
            - prediction: "Benign" or "Malicious"
            - confidence: float probability of the predicted class
            - probability_malicious: float raw probability of malicious class
            - inference_time_ms: float time taken for prediction in milliseconds
    """
    t0 = time.perf_counter()

    # Load model (cached after first call)
    model = _load_model(model_path)

    # Extract features from the raw URL
    features = extract_features(url).reshape(1, -1)

    # Handle NaN/Inf
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

    # Predict probability of malicious class
    prob_malicious: float = float(model.predict(features)[0])

    # Classify
    is_malicious = prob_malicious >= threshold
    label = "Malicious" if is_malicious else "Benign"
    confidence = prob_malicious if is_malicious else (1.0 - prob_malicious)

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return {
        "prediction": label,
        "confidence": round(confidence, 4),
        "probability_malicious": round(prob_malicious, 4),
        "inference_time_ms": round(elapsed_ms, 3),
    }


# ============================================================================
# CLI Interface
# ============================================================================

if __name__ == "__main__":
    import sys

    test_urls = [
        "https://www.google.com",
        "https://accounts.psgitech.ac.in/realms/itech/protocol/openid-connect/auth?client_id=laudea",
        "http://192.168.1.1/admin/login.php",
        "http://free-iphone-giveaway.tk/claim?id=abc123",
        "https://paypal-secure-login.xyz/verify?user=john@email.com",
        "https://github.com/lightgbm",
    ]

    # Allow CLI arguments
    if len(sys.argv) > 1:
        test_urls = sys.argv[1:]

    print("=" * 70)
    print("  PhishGuard LightGBM Inference")
    print("=" * 70)

    for url in test_urls:
        result = predict_url(url)
        status_icon = "🔴" if result["prediction"] == "Malicious" else "🟢"
        print(f"\n  {status_icon} {result['prediction']} ({result['confidence']:.1%} confidence)")
        print(f"     URL: {url[:80]}{'...' if len(url) > 80 else ''}")
        print(f"     P(malicious): {result['probability_malicious']:.4f}")
        print(f"     Inference:    {result['inference_time_ms']:.3f} ms")

    print("\n" + "=" * 70)
