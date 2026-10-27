# PhishGuard – Real-Time Scam & Phishing Detection Browser Extension

A full-stack browser extension for detecting scam and phishing websites using machine learning.

**Main repair branch:** all URL, MiniLM, DOM and explanation features are active. Use the [pairing and startup guide](docs/MAIN_REPAIR_SETUP.md) before starting the API. See the [repair and real-browser verification report](MAIN_REPAIR_REPORT.md) for executed checks and remaining model-accuracy limitations.

## 🏗️ Project Structure

```
phishguard/
├── extension/          # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── popup/
│   ├── background/
│   ├── content/
│   └── assets/
├── backend/            # Flask REST API
│   ├── app/
│   ├── config/
│   └── tests/
├── models/             # ML Models & Training
│   ├── training/
│   └── saved/
├── datasets/           # Training & Test Datasets
│   ├── raw/
│   └── processed/
└── docs/               # Documentation
```

## 🛠️ Tech Stack

### Frontend

- Chrome Extension (Manifest V3)
- Vanilla JavaScript
- HTML + CSS

### Backend

- Python 3.10+
- Flask
- REST API

### Machine Learning

- scikit-learn
- LightGBM URL model
- transformers (fine-tuned MiniLM)
- LightGBM native TreeSHAP explanations
- numpy, pandas

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+ (for extension development)
- Chrome Browser

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Extension Setup

The extension is plain JavaScript and requires no npm build. Load the `extension` folder directly, then configure its Connection settings as described in the startup guide.

### Loading the Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `extension` folder

## 📝 License

MIT License

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines in `docs/CONTRIBUTING.md`.
