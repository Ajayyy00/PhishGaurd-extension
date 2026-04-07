# PhishGuard – Real-Time Scam & Phishing Detection Browser Extension

A production-ready full-stack browser extension for detecting scam and phishing websites in real-time using machine learning.

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
- transformers (DistilBERT)
- SHAP (Explainability)
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
