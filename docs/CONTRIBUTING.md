# Contributing to PhishGuard

Thank you for your interest in contributing to PhishGuard!

## Development Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- Chrome Browser

### Getting Started

1. Fork the repository
2. Clone your fork
3. Set up the backend:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. Set up the extension:
   ```bash
   cd extension
   npm install
   ```

## Code Style

### Python

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for all functions and classes

### JavaScript

- Use ES6+ features
- Follow consistent naming conventions
- Add JSDoc comments

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Write/update tests
4. Ensure all tests pass
5. Submit a pull request

## Reporting Issues

When reporting issues, please include:

- Description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details
