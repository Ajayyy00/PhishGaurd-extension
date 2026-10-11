"""
PhishGuard Analyzer Service
Main analysis orchestrator for URL, text, and DOM analysis
"""

from typing import Dict, Any, List
from urllib.parse import urlparse
import re
import time
import json
import hashlib
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from threading import BoundedSemaphore
from .cache import TTLCache
from .risk import combine, risk_level, POLICY_VERSION, BLOCK_THRESHOLD

_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix='phishguard')
_SLOTS = BoundedSemaphore(8)


def submit_detection(fn, *args):
    if not _SLOTS.acquire(blocking=False):
        return None
    try:
        future = _POOL.submit(fn, *args)
    except Exception:
        _SLOTS.release()
        raise
    future.add_done_callback(lambda _: _SLOTS.release())
    return future

from .url_detector import predict_url_risk, get_detector
from .nlp_detector import predict_text_risk, get_nlp_detector
from .dom_detector import analyze_dom_similarity, get_dom_detector


class AnalyzerService:
    """
    Central service for analyzing URLs, text content, and DOM structures.
    Combines LightGBM URL, MiniLM text and DOM similarity analysis.
    """
    
    # Known safe domains
    SAFE_DOMAINS = {
        # Search & Tech Giants
        'google.com', 'youtube.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
        'microsoft.com', 'apple.com', 'amazon.com', 'aws.amazon.com',
        # Social Media
        'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'pinterest.com', 'tiktok.com', 'snapchat.com',
        # AI & Dev Tools
        'chatgpt.com', 'openai.com', 'anthropic.com', 'claude.ai',
        'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
        'npmjs.com', 'pypi.org', 'docker.com', 'vercel.com', 'netlify.com',
        # Communication
        'whatsapp.com', 'discord.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
        'gmail.com', 'outlook.com', 'proton.me', 'mail.google.com',
        # Entertainment
        'netflix.com', 'spotify.com', 'twitch.tv', 'hulu.com', 'disneyplus.com',
        'primevideo.com', 'hbomax.com', 'crunchyroll.com',
        # Shopping & Payments
        'paypal.com', 'ebay.com', 'etsy.com', 'shopify.com', 'stripe.com',
        # Education & Reference
        'wikipedia.org', 'medium.com', 'notion.so', 'coursera.org', 'udemy.com',
        # Cloud Services
        'dropbox.com', 'drive.google.com', 'onedrive.live.com', 'icloud.com',
        # News
        'cnn.com', 'bbc.com', 'nytimes.com', 'theguardian.com', 'reuters.com'
    }
    
    # Urgency phrases in content
    URGENCY_PHRASES = [
        'act now', 'limited time', 'expire', 'suspend', 'verify immediately',
        'confirm your', 'update your', 'unusual activity', 'unauthorized',
        'click here immediately', 'account will be', 'within 24 hours'
    ]
    
    def __init__(self, cache_size=512, cache_ttl=86400, timeout=20):
        self._cache = TTLCache(cache_size, cache_ttl)
        self.timeout = timeout
        model_dir = Path(__file__).resolve().parents[2] / 'models' / 'saved'
        files = [model_dir / 'lgbm_url_model.txt'] + sorted((model_dir / 'nlp_phish_model').glob('*'))
        files = [p for p in files if p.is_file()]
        revision = [(p.name, p.stat().st_size, p.stat().st_mtime_ns) if p.exists() else (p.name, 'missing') for p in files]
        self.model_revision = hashlib.sha256(json.dumps(revision).encode()).hexdigest()[:16]

    def _analyze_url(self, url):
        detector = get_detector()
        score = detector.predict_url_risk(url, strict=True)
        details = self._get_url_details(url, score)
        return {'risk': score, 'explanations': details['explanations'], 'features': details}

    def analyze(self, url: str, text: str = '', dom: Dict = None, force_refresh=False) -> Dict[str, Any]:
        """Bounded parallel inference; unavailable detectors never vote as zero."""
        start = time.monotonic()
        text, dom = text or '', dom or {}
        inputs = {'url': url, 'text': text, 'dom': dom, 'version': POLICY_VERSION,
                  'model': self.model_revision, 'timeout': self.timeout}
        key = hashlib.sha256(json.dumps(inputs, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        cached = None if force_refresh else self._cache.get(key)
        if cached is not None:
            cached['cached'] = True
            return cached
        jobs = {'url': (self._analyze_url, (url,))}
        if len(text.strip()) >= 20:
            jobs['nlp'] = (self._analyze_text, (text,))
        if dom:
            jobs['dom'] = (self._analyze_dom, (dom, url))
        futures = {name: submit_detection(fn, *args) for name, (fn, args) in jobs.items()}
        # Explainability is preserved but does not prevent faster detector work.
        futures['shap'] = submit_detection(self._get_url_explanations, url)
        running = [f for name, f in futures.items() if name != 'shap' and f is not None]
        if running:
            wait(running, timeout=self.timeout)
        if futures['shap'] is not None:
            wait([futures['shap']], timeout=min(1.5, max(0, self.timeout - (time.monotonic() - start))))
        scores = {'url': None, 'nlp': None, 'dom': None}
        statuses = {name: {'status': 'not_run', 'source': None} for name in scores}
        results, errors, explanations = {}, [], []
        for name, future in futures.items():
            status = 'ok'
            try:
                if future is None:
                    raise RuntimeError('capacity')
                if not future.done():
                    future.cancel()
                    status = 'timed_out'
                    raise TimeoutError()
                value = future.result()
                if name == 'shap':
                    results['shap'] = value
                    continue
                combine({name: value['risk']})  # Enforce finite numeric detector outputs.
                if value['risk'] is None:
                    raise RuntimeError('unavailable')
                scores[name] = value['risk']
                statuses[name] = {'status': 'ok', 'source': 'model' if name != 'dom' else 'similarity'}
                results[name] = value
                explanations.extend(value.get('explanations', []))
            except Exception as error:
                if status != 'timed_out':
                    status = 'failed'
                if name in statuses:
                    statuses[name] = {'status': status, 'source': None}
                errors.append({'detector': name, 'status': status, 'message': f'{name.upper()} analysis {status.replace("_", " ")}'})
                logging.getLogger(__name__).warning('%s detector %s (%s)', name, status, type(error).__name__)
        if scores['url'] is None:
            # Preserve the existing independent URL fallback, clearly labeled.
            from .url_detector import URLDetector
            score = URLDetector._basic_heuristic_score(None, url)
            scores['url'] = score
            statuses['url']['source'] = 'heuristic_fallback'
            explanations.append({'type': 'warning', 'category': 'url', 'message': 'URL model unavailable; using reduced-confidence URL heuristics'})
        if statuses['url']['status'] == 'ok':
            explanations.extend(results.get('shap', []))
        explanations.extend({'type': 'warning', 'category': 'system', 'message': e['message']} for e in errors)
        score = combine(scores)
        degraded = any(s['status'] in ('failed', 'timed_out') for s in statuses.values())
        level = risk_level(score, degraded)
        active = [name for name, value in scores.items() if value is not None]
        stage = 'full' if len(active) == 3 else '_'.join(active)
        if stage == 'url':
            stage = 'url_only'
        url_details = results.get('url', {}).get('features', {})
        result = {
            'url': url, 'url_risk': scores['url'], 'nlp_risk': scores['nlp'], 'dom_risk': scores['dom'],
            'final_score': score, 'risk_score': score, 'risk_level': level, 'level': level,
            'is_phishing': score is not None and score > 70,
            'should_block': (scores['url'] or 0) >= BLOCK_THRESHOLD or (score or 0) > 70,
            'analysis_stage': stage, 'detectors': statuses, 'degraded': degraded,
            'confidence': None, 'breakdown': scores, 'errors': errors, 'explanations': explanations,
            'explanation': explanations[0]['message'] if explanations else 'Analysis complete',
            'suspicious_phrases': results.get('nlp', {}).get('suspicious_phrases', []),
            'form_keywords': results.get('nlp', {}).get('form_keywords', []),
            'features': {'protocol': url_details.get('protocol', ''), 'hostname': url_details.get('hostname', ''),
                         'riskFactors': url_details.get('risk_factors', []), 'safeFactors': url_details.get('safe_factors', [])},
            'response_time_ms': int((time.monotonic() - start) * 1000), 'cached': False,
            'policy_version': POLICY_VERSION, 'model_version': self.model_revision,
        }
        if not errors:
            self._cache.put(key, result)
        return result

    def _get_url_explanations(self, url: str) -> List[Dict[str, Any]]:
        """Get SHAP explanations for URL (computationally expensive, run in parallel)."""
        explanations = []
        try:
            shap_explanations = get_detector().explain_prediction(url)
            for exp in shap_explanations:
                explanations.append({
                    'type': 'danger', # SHAP only returns positive risk contributors
                    'category': 'ml',
                    'message': f"ML Model: {exp['feature']} (+{exp['impact']:.2f})"
                })
        except Exception as e:
            raise RuntimeError("SHAP explanation unavailable") from None
        return explanations

    def _get_url_details(self, url: str, ml_score=None) -> Dict[str, Any]:
        """Extract URL details and generate explanations based on ML score."""
        risk_factors = []
        safe_factors = []
        explanations = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            path = parsed.path or ''
            
            # Get ML score for context
            ml_score = predict_url_risk(url) if ml_score is None else ml_score
            
            # Protocol check
            if parsed.scheme == 'https':
                safe_factors.append('secure_connection')
            elif parsed.scheme == 'http':
                risk_factors.append('insecure_http')
                explanations.append({
                    'type': 'warning',
                    'category': 'url',
                    'message': 'Site uses insecure HTTP connection'
                })
            
            # IP address check
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                risk_factors.append('ip_address_url')
                explanations.append({
                    'type': 'danger',
                    'category': 'url',
                    'message': 'URL uses IP address instead of domain name'
                })
            
            # @ symbol check
            if '@' in url:
                risk_factors.append('suspicious_at_symbol')
                explanations.append({
                    'type': 'danger',
                    'category': 'url',
                    'message': 'URL contains @ symbol (potential redirect attack)'
                })
            
            # Subdomain count
            subdomain_count = len(hostname.split('.'))
            has_subdomain = subdomain_count > 2
            if subdomain_count > 4:
                risk_factors.append('excessive_subdomains')
                explanations.append({
                    'type': 'warning',
                    'category': 'url',
                    'message': f'URL has {subdomain_count} subdomain levels'
                })
            
            # Suspicious TLD check
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.buzz']
            for tld in suspicious_tlds:
                if hostname.endswith(tld):
                    risk_factors.append('suspicious_tld')
                    explanations.append({
                        'type': 'danger',
                        'category': 'url',
                        'message': f'Uses high-risk domain extension ({tld})'
                    })
                    break
            
            # Known safe domain check
            for safe_domain in self.SAFE_DOMAINS:
                if hostname == safe_domain or hostname.endswith('.' + safe_domain):
                    safe_factors.append('known_safe_domain')
                    explanations.append({
                        'type': 'safe',
                        'category': 'url',
                        'message': 'This is a known trusted domain'
                    })
                    break
            
            # High ML risk explanation
            if ml_score > 70:
                explanations.append({
                    'type': 'danger',
                    'category': 'ml',
                    'message': f'URL model and URL indicators produced risk score {ml_score}/100'
                })
            elif ml_score > 40:
                explanations.append({
                    'type': 'warning',
                    'category': 'ml',
                    'message': f'ML model detected moderate risk ({ml_score}%)'
                })
            
            return {
                'risk_factors': risk_factors,
                'safe_factors': safe_factors,
                'explanations': explanations,
                'protocol': parsed.scheme + ':' if parsed.scheme else '',
                'hostname': hostname,
                'has_subdomain': has_subdomain,
                'hostname_length': len(hostname),
                'path_depth': len([p for p in path.split('/') if p]),
                'has_query': bool(parsed.query)
            }
            
        except Exception as e:
            print(f"URL parsing error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'risk_factors': ['parse_error'],
                'safe_factors': [],
                'explanations': [{'type': 'warning', 'category': 'url', 'message': 'Could not parse URL'}],
                'protocol': '',
                'hostname': '',
                'has_subdomain': False,
                'hostname_length': 0,
                'path_depth': 0,
                'has_query': False
            }
    
    def _analyze_text(self, text: str) -> Dict[str, Any]:
        """Analyze page text content using ML-based NLP detection."""
        if not text or len(text.strip()) < 20:
            return {'risk': 0, 'explanations': [], 'suspicious_phrases': [], 'form_keywords': []}
        
        # Use ML-based NLP detector
        nlp_detector = get_nlp_detector()
        nlp_result = nlp_detector.predict_risk(text)
        if not nlp_result.get('model_used'):
            raise RuntimeError('NLP model unavailable')
        
        risk = nlp_result.get('score', 0)
        suspicious_phrases = nlp_result.get('suspicious_phrases', [])
        form_keywords = nlp_result.get('form_keywords', [])
        explanations = []
        
        # Get NLP Explanations (SHAP/Coefficients)
        try:
            nlp_explanations = nlp_detector.explain_prediction(text)
            for exp in nlp_explanations:
                explanations.append({
                    'type': 'danger',
                    'category': 'ml',
                    'message': f"NLP Model: {exp['feature']} (+{exp['impact']:.2f})"
                })
        except Exception as e:
            print(f"NLP explanation failed: {e}")
        
        # Add explanations for detected suspicious phrases
        if suspicious_phrases:
            explanations.append({
                'type': 'warning',
                'category': 'content',
                'message': f'Found {len(suspicious_phrases)} suspicious phrase(s): {", ".join(suspicious_phrases[:3])}'
            })
        
        # Add explanations for form keywords
        if form_keywords:
            exp_type = 'danger' if any(k in ['password', 'ssn', 'cvv', 'pin'] for k in form_keywords) else 'warning'
            explanations.append({
                'type': exp_type,
                'category': 'content',
                'message': f'Page requests sensitive info: {", ".join(form_keywords[:3])}'
            })
        
        # Add ML confidence explanation if high risk
        if risk >= 50:
            explanations.append({
                'type': 'danger',
                'category': 'ml',
                'message': f'NLP model and text indicators produced risk score {risk}/100'
            })
        
        return {
            'risk': min(100, risk),
            'explanations': explanations,
            'suspicious_phrases': suspicious_phrases,
            'form_keywords': form_keywords
        }
    
    def _analyze_dom(self, dom: Dict, url: str = '') -> Dict[str, Any]:
        """Analyze DOM structure using similarity detection."""
        if not dom:
            return {'risk': 0, 'explanations': [], 'matched_template': None, 'similarity': 0}
        
        # Use DOM similarity detector
        dom_result = analyze_dom_similarity(dom, url)
        
        risk = dom_result.get('score', 0)
        explanations = []
        
        matched_template = dom_result.get('matched_template')
        similarity = dom_result.get('similarity', 0)
        is_mismatch = dom_result.get('is_domain_mismatch', False)
        
        # Generate explanations based on results
        if matched_template and is_mismatch:
            explanations.append({
                'type': 'danger',
                'category': 'dom',
                'message': f'Page structure matches {matched_template.upper()} ({similarity}% similar) but domain is different!'
            })
        elif matched_template and similarity > 50:
            explanations.append({
                'type': 'info',
                'category': 'dom',
                'message': f'Page structure similar to {matched_template.upper()} ({similarity}%)'
            })
        
        # Check for credential forms
        fingerprint = dom_result.get('fingerprint', {})
        if fingerprint.get('has_credential_form'):
            if is_mismatch:
                explanations.append({
                    'type': 'warning',
                    'category': 'dom',
                    'message': 'Login form detected on suspicious domain'
                })
        
        # Check stats-based heuristics as fallback
        stats = dom.get('stats', {})
        form_count = stats.get('forms', 0)
        input_count = stats.get('inputs', 0)
        link_count = stats.get('links', 0)
        
        if input_count > 5 and link_count < 10 and risk < 20:
            risk += 10
            explanations.append({
                'type': 'info',
                'category': 'dom',
                'message': 'Page has many input fields with few navigation links'
            })
        
        return {
            'risk': min(100, risk),
            'explanations': explanations,
            'matched_template': matched_template,
            'similarity': similarity
        }
    
    def _get_risk_level(self, score: int) -> str:
        return risk_level(score)
