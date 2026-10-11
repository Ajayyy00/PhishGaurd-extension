"""Real application runner for an isolated E2E process (token only in env)."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'backend'))
from app import create_app
from services.url_detector import get_detector
from services.nlp_detector import get_nlp_detector

# Warm both saved models so cold library imports do not consume browser deadlines.
get_detector().explain_prediction('http://verify-paypal-account.xyz/login')
get_nlp_detector().predict_risk('Our community library provides books and reading rooms for families.')
app = create_app('production')
app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5057')),debug=False,use_reloader=False)
