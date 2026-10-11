# PhishGuard – Real-Time Scam & Phishing Detection Browser Extension

A full-stack browser extension for detecting scam and phishing websites using machine learning.

**Phase 1:** all modules remain enabled. Start with [secure pairing and test instructions](docs/PHASE1_SETUP.md) before running the API. Authentication is now required; the older startup examples below do not configure pairing. See [the verification report](PHASE1_COMPLETION_REPORT.md) for executed checks and known limitations, including model false positives and asynchronous blocking.

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
- LightGBM URL classifier
- transformers (fine-tuned MiniLM)
- Native LightGBM TreeSHAP (URL explainability)
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

```bash
cd extension
npm install
```

### Loading the Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `extension` folder

## 📝 License

MIT License

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines in `docs/CONTRIBUTING.md`.
