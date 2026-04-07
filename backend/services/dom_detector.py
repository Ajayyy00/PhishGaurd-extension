"""
PhishGuard DOM Similarity Detector
Detects phishing by comparing DOM structure to known site templates
"""

import re
import math
from typing import Dict, Any, List, Tuple, Optional
from collections import Counter
from urllib.parse import urlparse


class DOMDetector:
    """
    Detects phishing attempts by comparing DOM structures to known site templates.
    Uses structural fingerprinting and cosine similarity for efficient comparison.
    """
    
    # Template fingerprints for known sites
    # Format: domain -> structural features
    SITE_TEMPLATES = {
        'paypal': {
            'domain': 'paypal.com',
            'features': {
                # Form structure
                'login_form': True,
                'password_field': True,
                'email_field': True,
                # Branding elements
                'logo_keywords': ['paypal', 'pp'],
                'form_action_domain': 'paypal.com',
                # Structural patterns
                'typical_inputs': 3,
                'typical_forms': 1,
                'has_captcha': False,
                # Tag signature (normalized counts)
                'tag_signature': {'form': 1, 'input': 4, 'button': 2, 'div': 20, 'span': 15}
            }
        },
        'gmail': {
            'domain': 'google.com',
            'features': {
                'login_form': True,
                'password_field': True,
                'email_field': True,
                'logo_keywords': ['google', 'gmail'],
                'form_action_domain': 'google.com',
                'typical_inputs': 2,
                'typical_forms': 1,
                'has_captcha': False,
                'tag_signature': {'form': 1, 'input': 3, 'button': 2, 'div': 25, 'span': 20}
            }
        },
        'facebook': {
            'domain': 'facebook.com',
            'features': {
                'login_form': True,
                'password_field': True,
                'email_field': True,
                'logo_keywords': ['facebook', 'fb', 'meta'],
                'form_action_domain': 'facebook.com',
                'typical_inputs': 3,
                'typical_forms': 1,
                'has_captcha': False,
                'tag_signature': {'form': 1, 'input': 4, 'button': 3, 'div': 30, 'span': 25}
            }
        },
        'amazon': {
            'domain': 'amazon.com',
            'features': {
                'login_form': True,
                'password_field': True,
                'email_field': True,
                'logo_keywords': ['amazon', 'smile'],
                'form_action_domain': 'amazon.com',
                'typical_inputs': 3,
                'typical_forms': 1,
                'has_captcha': True,
                'tag_signature': {'form': 2, 'input': 5, 'button': 3, 'div': 35, 'span': 20}
            }
        },
        'bank': {
            'domain': 'bank',  # Generic bank template
            'features': {
                'login_form': True,
                'password_field': True,
                'email_field': False,
                'account_field': True,
                'logo_keywords': ['bank', 'secure', 'online banking'],
                'form_action_domain': None,
                'typical_inputs': 4,
                'typical_forms': 1,
                'has_captcha': True,
                'has_security_image': True,
                'tag_signature': {'form': 1, 'input': 5, 'button': 2, 'div': 25, 'span': 15, 'img': 5}
            }
        }
    }
    
    # Keywords that indicate credential forms
    CREDENTIAL_KEYWORDS = [
        'password', 'passwd', 'pass', 'pwd',
        'login', 'signin', 'sign-in', 'log-in',
        'email', 'username', 'user', 'account',
        'ssn', 'social', 'security',
        'card', 'cvv', 'expiry', 'credit'
    ]
    
    def __init__(self):
        pass
    
    def analyze_dom(self, dom: Dict, url: str = '') -> Dict[str, Any]:
        """
        Analyze DOM structure and compare to known templates.
        
        Args:
            dom: DOM structure as JSON (stats, elements, etc.)
            url: Current page URL
            
        Returns:
            {
                'score': 0-100 risk score,
                'matched_template': template name if matched,
                'similarity': similarity percentage,
                'is_domain_mismatch': bool,
                'fingerprint': structural fingerprint
            }
        """
        if not dom:
            return {
                'score': 0,
                'matched_template': None,
                'similarity': 0,
                'is_domain_mismatch': False,
                'fingerprint': {}
            }
        
        # Extract current domain
        current_domain = ''
        if url:
            try:
                parsed = urlparse(url)
                current_domain = parsed.hostname or ''
            except:
                pass
        
        # Generate fingerprint for current page
        fingerprint = self._generate_fingerprint(dom)
        
        # Compare against all templates
        best_match = None
        best_similarity = 0.0
        
        for template_name, template_data in self.SITE_TEMPLATES.items():
            similarity = self._compute_similarity(fingerprint, template_data['features'])
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = template_name
        
        # Check for domain mismatch
        is_domain_mismatch = False
        if best_match and best_similarity > 0.5:
            expected_domain = self.SITE_TEMPLATES[best_match]['domain']
            if expected_domain and current_domain:
                # Check if current domain is NOT the expected domain
                if expected_domain not in current_domain.lower():
                    is_domain_mismatch = True
        
        # Calculate risk score
        score = 0
        if best_similarity >= 0.7 and is_domain_mismatch:
            # High similarity to known site but wrong domain = high risk
            score = int(50 + (best_similarity * 50))
        elif best_similarity >= 0.5 and is_domain_mismatch:
            # Moderate similarity with domain mismatch
            score = int(30 + (best_similarity * 40))
        elif fingerprint.get('has_credential_form') and is_domain_mismatch:
            # Has credential form on mismatched domain
            score = 40
        elif fingerprint.get('suspicious_form_action'):
            # Form submits to different domain
            score = 35
        
        return {
            'score': min(100, score),
            'matched_template': best_match if best_similarity > 0.5 else None,
            'similarity': round(best_similarity * 100, 1),
            'is_domain_mismatch': is_domain_mismatch,
            'fingerprint': fingerprint
        }
    
    def _generate_fingerprint(self, dom: Dict) -> Dict[str, Any]:
        """Generate structural fingerprint from DOM data."""
        fingerprint = {
            'has_credential_form': False,
            'has_password_field': False,
            'has_email_field': False,
            'form_count': 0,
            'input_count': 0,
            'tag_signature': {},
            'suspicious_form_action': False,
            'detected_brand': None
        }
        
        stats = dom.get('stats', {})
        
        # Basic counts
        fingerprint['form_count'] = stats.get('forms', 0)
        fingerprint['input_count'] = stats.get('inputs', 0)
        
        # Tag signature from stats
        fingerprint['tag_signature'] = {
            'form': stats.get('forms', 0),
            'input': stats.get('inputs', 0),
            'a': stats.get('links', 0),
            'script': stats.get('scripts', 0),
            'iframe': stats.get('iframes', 0)
        }
        
        # Check for credential-related forms
        forms = dom.get('forms', [])
        inputs = dom.get('inputs', [])
        
        # Analyze input fields
        for inp in inputs if isinstance(inputs, list) else []:
            inp_type = str(inp.get('type', '')).lower()
            inp_name = str(inp.get('name', '')).lower()
            inp_id = str(inp.get('id', '')).lower()
            
            if inp_type == 'password':
                fingerprint['has_password_field'] = True
                fingerprint['has_credential_form'] = True
            
            if inp_type == 'email' or 'email' in inp_name or 'email' in inp_id:
                fingerprint['has_email_field'] = True
            
            # Check for credential keywords
            for keyword in self.CREDENTIAL_KEYWORDS:
                if keyword in inp_name or keyword in inp_id:
                    fingerprint['has_credential_form'] = True
                    break
        
        # Analyze form actions
        for form in forms if isinstance(forms, list) else []:
            action = str(form.get('action', '')).lower()
            if action and action.startswith('http'):
                # Form submits to external URL
                fingerprint['suspicious_form_action'] = True
        
        # Try to detect brand from DOM content
        visible_text = dom.get('visibleText', '').lower() if dom.get('visibleText') else ''
        title = dom.get('title', '').lower() if dom.get('title') else ''
        
        brand_indicators = {
            'paypal': ['paypal', 'pp'],
            'gmail': ['gmail', 'google'],
            'facebook': ['facebook', 'fb', 'meta'],
            'amazon': ['amazon'],
            'bank': ['bank', 'banking', 'online banking']
        }
        
        for brand, keywords in brand_indicators.items():
            for keyword in keywords:
                if keyword in visible_text or keyword in title:
                    fingerprint['detected_brand'] = brand
                    break
            if fingerprint['detected_brand']:
                break
        
        return fingerprint
    
    def _compute_similarity(self, fingerprint: Dict, template_features: Dict) -> float:
        """
        Compute similarity between page fingerprint and template features.
        Uses weighted feature matching and cosine similarity for tag signatures.
        """
        score = 0.0
        weights_sum = 0.0
        
        # Feature comparisons with weights
        comparisons = [
            # (fingerprint_key, template_key, weight, comparison_func)
            ('has_password_field', 'password_field', 2.0, 'bool'),
            ('has_email_field', 'email_field', 1.5, 'bool'),
            ('has_credential_form', 'login_form', 2.0, 'bool'),
            ('form_count', 'typical_forms', 1.0, 'numeric'),
            ('input_count', 'typical_inputs', 1.0, 'numeric'),
        ]
        
        for fp_key, tmpl_key, weight, cmp_type in comparisons:
            if tmpl_key not in template_features:
                continue
            
            fp_val = fingerprint.get(fp_key)
            tmpl_val = template_features.get(tmpl_key)
            
            if cmp_type == 'bool':
                if fp_val == tmpl_val:
                    score += weight
            elif cmp_type == 'numeric':
                if tmpl_val and tmpl_val > 0:
                    ratio = min(fp_val, tmpl_val) / max(fp_val, tmpl_val) if fp_val else 0
                    score += weight * ratio
            
            weights_sum += weight
        
        # Tag signature cosine similarity
        fp_tags = fingerprint.get('tag_signature', {})
        tmpl_tags = template_features.get('tag_signature', {})
        
        if fp_tags and tmpl_tags:
            tag_sim = self._cosine_similarity(fp_tags, tmpl_tags)
            score += 2.0 * tag_sim
            weights_sum += 2.0
        
        # Brand match bonus
        detected_brand = fingerprint.get('detected_brand')
        if detected_brand:
            brand_match_weight = 3.0
            # This will be factored into the score if brand matches template
            weights_sum += brand_match_weight
            for tmpl_name, tmpl_data in self.SITE_TEMPLATES.items():
                if detected_brand == tmpl_name:
                    score += brand_match_weight
                    break
        
        return score / weights_sum if weights_sum > 0 else 0.0
    
    def _cosine_similarity(self, vec1: Dict, vec2: Dict) -> float:
        """Compute cosine similarity between two feature vectors."""
        # Get all keys
        all_keys = set(vec1.keys()) | set(vec2.keys())
        
        # Convert to vectors
        v1 = [vec1.get(k, 0) for k in all_keys]
        v2 = [vec2.get(k, 0) for k in all_keys]
        
        # Compute dot product
        dot_product = sum(a * b for a, b in zip(v1, v2))
        
        # Compute magnitudes
        mag1 = math.sqrt(sum(a * a for a in v1))
        mag2 = math.sqrt(sum(b * b for b in v2))
        
        if mag1 == 0 or mag2 == 0:
            return 0.0
        
        return dot_product / (mag1 * mag2)


# Singleton instance
_dom_detector_instance = None


def get_dom_detector() -> DOMDetector:
    """Get or create singleton DOM detector instance."""
    global _dom_detector_instance
    if _dom_detector_instance is None:
        _dom_detector_instance = DOMDetector()
    return _dom_detector_instance


def analyze_dom_similarity(dom: Dict, url: str = '') -> Dict[str, Any]:
    """
    Convenience function to analyze DOM similarity.
    
    Args:
        dom: DOM structure as JSON
        url: Current page URL
        
    Returns:
        Analysis result with score and matched template
    """
    return get_dom_detector().analyze_dom(dom, url)
