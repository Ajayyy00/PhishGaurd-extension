"""
PhishGuard NLP Detector
Text-based phishing detection using TF-IDF + Logistic Regression
"""

import re
import os
import torch
from typing import Dict, Any, List, Tuple
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Model storage path
NLP_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'saved', 'nlp_phish_model')


class NLPDetector:
    """
    NLP-based phishing detection using TF-IDF embeddings and Logistic Regression.
    Detects suspicious phrases and form-related keywords.
    """
    
    # Suspicious phrases commonly found in phishing
    SUSPICIOUS_PHRASES = [
        # Urgency
        'act now', 'urgent', 'immediately', 'expire', 'limited time',
        'within 24 hours', 'within 48 hours', 'last chance', 'final warning',
        'action required', 'respond immediately', 'don\'t delay',
        # Verification/Security
        'verify your account', 'confirm your identity', 'update your information',
        'verify your identity', 'security alert', 'unusual activity',
        'suspicious activity', 'unauthorized access', 'account suspended',
        'account locked', 'account disabled', 'account will be closed',
        # Credentials
        'enter your password', 'confirm your password', 'update your password',
        'reset your password', 'login credentials', 'verify your email',
        'otp', 'one time password', 'verification code', 'security code',
        'pin number', 'cvv', 'credit card', 'debit card', 'bank account',
        'social security', 'ssn', 'tax id',
        # Click actions
        'click here', 'click now', 'click below', 'click the link',
        'click the button', 'log in now', 'sign in now', 'access now',
        # Prizes/Money
        'you have won', 'winner', 'congratulations', 'claim your prize',
        'lottery', 'free gift', 'cash prize', 'million dollars',
        # Threats
        'legal action', 'police', 'arrest', 'lawsuit', 'penalty',
        'your account will be', 'failure to', 'if you don\'t',
    ]
    
    # Form-related sensitive keywords
    FORM_KEYWORDS = [
        'password', 'passwd', 'secret', 'pin', 'cvv', 'cvc',
        'card number', 'account number', 'routing number',
        'social security', 'ssn', 'date of birth', 'dob',
        'mother\'s maiden', 'security question', 'username',
        'login', 'signin', 'email address', 'phone number'
    ]
    
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._load_model()
    
    def _load_model(self):
        """Load the fine-tuned HuggingFace model."""
        if os.path.exists(NLP_MODEL_PATH):
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(NLP_MODEL_PATH)
                self.model = AutoModelForSequenceClassification.from_pretrained(NLP_MODEL_PATH)
                self.model.to(self.device)
                self.model.eval()
            except Exception as e:
                print(f"Error loading NLP model from {NLP_MODEL_PATH}: {e}")
                self.tokenizer = None
                self.model = None
        else:
            print(f"NLP model directory not found at {NLP_MODEL_PATH}")
    
    def preprocess_text(self, text: str) -> str:
        """
        Preprocess text for analysis.
        - Convert to lowercase
        - Remove excessive whitespace
        - Remove special characters (keep alphanumeric and spaces)
        """
        if not text:
            return ''
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs
        text = re.sub(r'https?://\S+', ' ', text)
        
        # Remove email addresses
        text = re.sub(r'\S+@\S+', ' ', text)
        
        # Remove special characters, keep letters, numbers, spaces
        text = re.sub(r'[^a-z0-9\s]', ' ', text)
        
        # Remove excessive whitespace
        text = ' '.join(text.split())
        
        return text
    
    def detect_suspicious_phrases(self, text: str) -> List[str]:
        """
        Detect suspicious phrases in text.
        Returns list of found suspicious phrases.
        """
        if not text:
            return []
        
        text_lower = text.lower()
        found_phrases = []
        
        for phrase in self.SUSPICIOUS_PHRASES:
            if phrase in text_lower:
                found_phrases.append(phrase)
        
        return found_phrases
    
    def detect_form_keywords(self, text: str) -> List[str]:
        """
        Detect sensitive form-related keywords.
        """
        if not text:
            return []
        
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.FORM_KEYWORDS:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def explain_prediction(self, text: str) -> List[Dict[str, Any]]:
        """
        Explain why text was classified as phishing.
        Approximates impact by splitting sentences and evaluating them independently.
        """
        if not self.model or not self.tokenizer or not text:
            return []
            
        try:
            # Simple sentence splitting heuristic
            parts = [p.strip() for p in re.split(r'[.!?\n]', text) if len(p.strip()) > 5]
            if not parts:
                return []
                
            contributions = []
            
            # Calculate risk for each sentence segment
            for part in parts[:10]:  # Limit to 10 parts for performance
                processed = self.preprocess_text(part)
                if not processed:
                    continue
                    
                inputs = self.tokenizer(processed, return_tensors="pt", truncation=True, max_length=128)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    proba = torch.softmax(outputs.logits, dim=-1)[0].cpu().numpy()
                    phishing_prob = proba[1]
                
                # If a sentence individually is heavily phishing
                if phishing_prob > 0.5:
                    contributions.append({
                        'feature': f"Suspicious context: '{part[:50]}...'",
                        'impact': float(phishing_prob),
                        'raw_feature': part
                    })
            
            # Sort by impact
            contributions.sort(key=lambda x: x['impact'], reverse=True)
            return contributions[:5]
            
        except Exception as e:
            print(f"NLP explanation error: {e}")
            return []

    def predict_risk(self, text: str) -> Dict[str, Any]:
        """
        Predict phishing risk score for given text.
        
        Returns:
            {
                'score': 0-100 risk score,
                'suspicious_phrases': list of detected phrases,
                'form_keywords': list of detected form keywords,
                'confidence': model confidence
            }
        """
        if not text or len(text.strip()) < 10:
            return {
                'score': 0,
                'suspicious_phrases': [],
                'form_keywords': [],
                'confidence': 0.5
            }
        
        # Detect suspicious phrases
        suspicious_phrases = self.detect_suspicious_phrases(text)
        form_keywords = self.detect_form_keywords(text)
        
        # Calculate phrase-based score
        phrase_score = min(len(suspicious_phrases) * 15, 50)
        form_score = min(len(form_keywords) * 10, 30)
        
        # ML-based score prediction
        ml_score = 0
        confidence = 0.5
        
        if self.model and self.tokenizer:
            try:
                processed = self.preprocess_text(text)
                inputs = self.tokenizer(processed, return_tensors="pt", truncation=True, max_length=256)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    proba = torch.softmax(outputs.logits, dim=-1)[0].cpu().numpy()
                    phishing_prob = proba[1]
                
                ml_score = int(phishing_prob * 100)
                confidence = max(proba)
                
            except Exception as e:
                print(f"Transformers prediction error: {e}")
        
        # Combine scores (weighted)
        # ML: 50%, Phrases: 30%, Form keywords: 20%
        final_score = int(
            (ml_score * 0.5) +
            (phrase_score * 0.3) +
            (form_score * 0.2)
        )
        
        # Boost for multiple indicators
        if suspicious_phrases and form_keywords:
            final_score = min(100, final_score + 10)
        
        return {
            'score': max(0, min(100, final_score)),
            'suspicious_phrases': suspicious_phrases[:5],  # Limit to top 5
            'form_keywords': form_keywords[:5],
            'confidence': round(confidence, 2)
        }


# Singleton instance
_nlp_detector_instance = None


def get_nlp_detector() -> NLPDetector:
    """Get or create singleton NLP detector instance."""
    global _nlp_detector_instance
    if _nlp_detector_instance is None:
        _nlp_detector_instance = NLPDetector()
    return _nlp_detector_instance


def predict_text_risk(text: str) -> Dict[str, Any]:
    """
    Convenience function to predict text phishing risk.
    
    Args:
        text: Text content to analyze
        
    Returns:
        Risk analysis result with score and detected phrases
    """
    return get_nlp_detector().predict_risk(text)


def train_nlp_model() -> Dict[str, Any]:
    """
    Deprecated: training is now handled via the train_nlp.py pipeline.
    """
    print("Warning: train_nlp_model() is deprecated. Run train_nlp.py instead.")
    return {"status": "deprecated", "message": "Use the train_nlp.py script to fine-tune the MiniLM model."}
