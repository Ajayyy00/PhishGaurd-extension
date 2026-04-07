"""
PhishGuard Analyzer Service
Main analysis orchestrator for URL, text, and DOM analysis
"""

from typing import Dict, Any, List
from urllib.parse import urlparse
import re

from .url_detector import predict_url_risk, get_detector
from .nlp_detector import predict_text_risk, get_nlp_detector
from .dom_detector import analyze_dom_similarity, get_dom_detector


class AnalyzerService:
    """
    Central service for analyzing URLs, text content, and DOM structures.
    Uses ML-based URL detection with heuristic text and DOM analysis.
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
    
    def __init__(self):
        # Initialize URL detector (loads/trains model)
        self._url_detector = get_detector()
        
        # Performance: In-memory cache
        self._cache = {} # {url: (result, timestamp)}
        self._cache_ttl = 86400 # 24 hours
    
    def analyze(self, url: str, text: str = '', dom: Dict = None) -> Dict[str, Any]:
        """
        Perform full analysis on URL, text, and DOM.
        Optimized: URL first, then NLP + DOM in parallel.
        
        Args:
            url: The URL to analyze
            text: Visible text content from the page
            dom: DOM fingerprint structure
            
        Returns:
            Analysis result with risk scores and explanations
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time
        
        start_time = time.time()
        dom = dom or {}
        
        # Check cache (Backend caching)
        if url in self._cache:
            cached_data, timestamp = self._cache[url]
            if time.time() - timestamp < self._cache_ttl:
                print(f"[CACHE HIT] Returning cached analysis for {url}")
                return cached_data
            else:
                del self._cache[url] # Expired
        
        # Step 1: Run URL analysis FIRST (fastest and most critical)
        url_risk = predict_url_risk(url)
        url_result = self._get_url_details(url)
        
        # Step 2: Run NLP, DOM, and URL Explanations in PARALLEL
        nlp_result = {'risk': 0, 'explanations': [], 'suspicious_phrases': [], 'form_keywords': []}
        dom_result = {'risk': 0, 'explanations': [], 'matched_template': None, 'similarity': 0}
        url_shap_explanations = []
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Submit NLP analysis
            if text:
                futures['nlp'] = executor.submit(self._analyze_text, text)
            
            # Submit DOM analysis
            if dom:
                futures['dom'] = executor.submit(self._analyze_dom, dom, url)
                
            # Submit URL SHAP explanation (Slow)
            futures['url_exp'] = executor.submit(self._get_url_explanations, url)
            
            # Collect results as they complete
            for name, future in futures.items():
                try:
                    result = future.result(timeout=1.5)  # 1.5s timeout per task
                    if name == 'nlp':
                        nlp_result = result
                    elif name == 'dom':
                        dom_result = result
                    elif name == 'url_exp':
                        url_shap_explanations = result
                except Exception as e:
                    # Log but continue with default values
                    pass
        
        nlp_risk = nlp_result.get('risk', 0)
        dom_risk = dom_result.get('risk', 0)
        
        # Collect all explanations
        explanations = []
        explanations.extend(url_result.get('explanations', []))
        explanations.extend(url_shap_explanations)
        explanations.extend(nlp_result.get('explanations', []))
        explanations.extend(dom_result.get('explanations', []))
        
        # Calculate final score (weighted average)
        # Formula: 0.30 * url + 0.40 * nlp + 0.30 * dom
        final_score = int(
            (url_risk * 0.30) + 
            (nlp_risk * 0.40) + 
            (dom_risk * 0.30)
        )
        
        # Ensure score is in valid range
        final_score = max(0, min(100, final_score))
        
        # Override: If URL is explicitly malicious (100), force high risk
        if url_risk >= 90:
            final_score = max(final_score, 90)
        
        # Determine risk level
        # 0-30 -> Safe
        # 31-70 -> Suspicious
        # 71-100 -> Dangerous
        if final_score <= 30:
            risk_level = 'safe'
        elif final_score <= 70:
            risk_level = 'suspicious'
        else:
            risk_level = 'dangerous'
        
        # Calculate response time
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        result = {
            'url': url,
            'url_risk': url_risk,
            'nlp_risk': nlp_risk,
            'dom_risk': dom_risk,
            'final_score': final_score,
            'level': risk_level,  # Explicit level field
            'risk_level': risk_level, # Keep for backward compatibility
            'breakdown': {
                'url': url_risk,
                'nlp': nlp_risk,
                'dom': dom_risk
            },
            'is_phishing': final_score > 70,
            'confidence': 0.85 if url_risk > 50 else 0.75,
            'explanations': explanations,
            'suspicious_phrases': nlp_result.get('suspicious_phrases', []),
            'form_keywords': nlp_result.get('form_keywords', []),
            'response_time_ms': elapsed_ms,
            'features': {
                'protocol': url_result.get('protocol', ''),
                'hostname': url_result.get('hostname', ''),
                'hasSubdomain': url_result.get('has_subdomain', False),
                'hostnameLength': url_result.get('hostname_length', 0),
                'pathDepth': url_result.get('path_depth', 0),
                'hasQueryParams': url_result.get('has_query', False),
                'riskFactors': url_result.get('risk_factors', []),
                'safeFactors': url_result.get('safe_factors', [])
            }
        }
        
        # Cache the result
        self._cache[url] = (result, time.time())
        
        return result
    
    def _get_url_explanations(self, url: str) -> List[Dict[str, Any]]:
        """Get SHAP explanations for URL (computationally expensive, run in parallel)."""
        explanations = []
        try:
            shap_explanations = self._url_detector.explain_prediction(url)
            for exp in shap_explanations:
                explanations.append({
                    'type': 'danger', # SHAP only returns positive risk contributors
                    'category': 'ml',
                    'message': f"ML Model: {exp['feature']} (+{exp['impact']:.2f})"
                })
        except Exception as e:
            print(f"SHAP explanation failed: {e}")
        return explanations

    def _get_url_details(self, url: str) -> Dict[str, Any]:
        """Extract URL details and generate explanations based on ML score."""
        risk_factors = []
        safe_factors = []
        explanations = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            path = parsed.path or ''
            
            # Get ML score for context
            ml_score = predict_url_risk(url)
            
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
                    'message': f'ML model detected high phishing probability ({ml_score}%)'
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
                'message': f'NLP model detected high phishing probability ({risk}%)'
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
        """Convert numeric score to risk level string."""
        if score < 20:
            return 'safe'
        elif score < 40:
            return 'low'
        elif score < 60:
            return 'medium'
        elif score < 80:
            return 'high'
        return 'critical'
