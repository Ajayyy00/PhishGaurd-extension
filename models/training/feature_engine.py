"""
PhishGuard Feature Engineering Module
Ultra-fast numerical feature extraction from raw URL strings.

Design: Zero external network lookups. Pure string math.
Target: <0.1ms per URL extraction on modern hardware.
"""

import math
import re
from collections import Counter
from typing import Dict, List
from urllib.parse import urlparse, parse_qs

import numpy as np
import pandas as pd


# ============================================================================
# Feature Names (Ordered) — 22 features total
# ============================================================================

FEATURE_NAMES: List[str] = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "num_params",
    "num_at_symbols",
    "num_eq_signs",
    "num_ampersands",
    "has_ip_address",
    "has_https",
    "has_port",
    "entropy",
    "digit_ratio",
    "special_char_ratio",
    "subdomain_depth",
    "path_depth",
]


# ============================================================================
# Precompiled Regex Patterns
# ============================================================================

_RE_IP_ADDR = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_SPECIAL = re.compile(r"[^a-zA-Z0-9]")
_RE_DIGIT = re.compile(r"\d")


# ============================================================================
# Single-URL Feature Extraction (for inference)
# ============================================================================

def extract_features(url: str) -> np.ndarray:
    """
    Extract 22 numerical features from a single raw URL string.

    Args:
        url: Raw URL string (e.g., "https://example.com/path?q=1").

    Returns:
        1-D numpy float32 array of shape (22,).
    """
    if not url or not isinstance(url, str):
        return np.zeros(len(FEATURE_NAMES), dtype=np.float32)

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float32)

    hostname: str = parsed.hostname or ""
    path: str = parsed.path or ""
    query: str = parsed.query or ""
    fragment: str = parsed.fragment or ""

    url_len = len(url)
    safe_len = max(url_len, 1)

    features = np.array(
        [
            # --- Length Features ---
            url_len,                                          # url_length
            len(hostname),                                    # domain_length
            len(path),                                        # path_length
            len(query),                                       # query_length
            len(fragment),                                    # fragment_length
            # --- Count Features ---
            url.count("."),                                   # num_dots
            url.count("-"),                                   # num_hyphens
            url.count("_"),                                   # num_underscores
            url.count("/"),                                   # num_slashes
            sum(c.isdigit() for c in url),                    # num_digits
            query.count("&") + (1 if query else 0),           # num_params
            url.count("@"),                                   # num_at_symbols
            url.count("="),                                   # num_eq_signs
            url.count("&"),                                   # num_ampersands
            # --- Boolean Features ---
            float(bool(_RE_IP_ADDR.match(hostname))),         # has_ip_address
            float(parsed.scheme == "https"),                   # has_https
            float(bool(parsed.port and parsed.port not in (80, 443))),  # has_port
            # --- Statistical Features ---
            _shannon_entropy(url),                            # entropy
            sum(c.isdigit() for c in url) / safe_len,         # digit_ratio
            len(_RE_SPECIAL.findall(url)) / safe_len,         # special_char_ratio
            # --- Structural Features ---
            max(0, len(hostname.split(".")) - 2),             # subdomain_depth
            len([seg for seg in path.split("/") if seg]),      # path_depth
        ],
        dtype=np.float32,
    )

    return features


# ============================================================================
# Vectorised Batch Extraction (for training — leverages pandas)
# ============================================================================

def extract_features_batch(urls: pd.Series) -> np.ndarray:
    """
    Vectorised feature extraction over a pandas Series of URL strings.
    Uses pandas str accessors and numpy broadcasting for maximum throughput.

    Args:
        urls: pandas Series of raw URL strings.

    Returns:
        2-D numpy float32 array of shape (n_urls, 22).
    """
    # Ensure string dtype, fill NaN
    urls = urls.fillna("").astype(str)

    # Pre-parse all URLs (with error handling for malformed IPv6 etc.)
    def _safe_parse(u):
        try:
            return urlparse(u if "://" in u else f"http://{u}")
        except Exception:
            return urlparse("http://malformed.invalid")

    parsed = urls.apply(_safe_parse)

    def _safe_hostname(p):
        try:
            return p.hostname or ""
        except Exception:
            return ""

    def _safe_port(p):
        try:
            return p.port
        except Exception:
            return None

    hostnames = parsed.apply(_safe_hostname)
    paths = parsed.apply(lambda p: p.path or "")
    queries = parsed.apply(lambda p: p.query or "")
    fragments = parsed.apply(lambda p: p.fragment or "")
    schemes = parsed.apply(lambda p: p.scheme)
    ports = parsed.apply(_safe_port)

    url_len = urls.str.len().values.astype(np.float32)
    safe_len = np.maximum(url_len, 1.0)

    features = np.column_stack([
        # Length features
        url_len,
        hostnames.str.len().values.astype(np.float32),
        paths.str.len().values.astype(np.float32),
        queries.str.len().values.astype(np.float32),
        fragments.str.len().values.astype(np.float32),
        # Count features
        urls.str.count(r"\.").values.astype(np.float32),
        urls.str.count("-").values.astype(np.float32),
        urls.str.count("_").values.astype(np.float32),
        urls.str.count("/").values.astype(np.float32),
        urls.str.count(r"\d").values.astype(np.float32),
        queries.str.count("&").values.astype(np.float32) + (queries.str.len() > 0).values.astype(np.float32),
        urls.str.count("@").values.astype(np.float32),
        urls.str.count("=").values.astype(np.float32),
        urls.str.count("&").values.astype(np.float32),
        # Boolean features
        hostnames.apply(lambda h: float(bool(_RE_IP_ADDR.match(h)))).values.astype(np.float32),
        (schemes == "https").values.astype(np.float32),
        ports.apply(lambda p: float(bool(p and p not in (80, 443)))).values.astype(np.float32),
        # Statistical features
        urls.apply(_shannon_entropy).values.astype(np.float32),
        urls.str.count(r"\d").values.astype(np.float32) / safe_len,
        urls.apply(lambda u: len(_RE_SPECIAL.findall(u))).values.astype(np.float32) / safe_len,
        # Structural features
        hostnames.apply(lambda h: max(0, len(h.split(".")) - 2)).values.astype(np.float32),
        paths.apply(lambda p: len([s for s in p.split("/") if s])).values.astype(np.float32),
    ]).astype(np.float32)

    return features


# ============================================================================
# Internal Utilities
# ============================================================================

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string. Returns 0.0 for empty strings."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
        if count > 0
    )
