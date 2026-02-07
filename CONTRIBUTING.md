# Contributing to APScan

Thank you for your interest in contributing to APScan! We welcome contributions of all forms, including bug reports, feature requests, documentation improvements, and code changes.

## Development Setup

### Prerequisites
- **Python**: >= 3.10
- **Node.js**: >= 18
- **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/4nilsj/apscan.git
cd apscan
```

### 2. Backend Setup
We use `venv` for Python dependency management.

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies in editable mode
pip install -e .
pip install -r requirements-dev.txt  # If exists
```

### 3. Frontend Setup
The frontend is a React application built with Vite.

```bash
cd web
npm install
```

## Running Tests

### Backend Tests
We use `pytest` for backend testing.

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/rules/test_auth_bypass.py
```

### Frontend Tests
(Add frontend testing instructions if available, e.g., `npm test`)

## Code Style

- **Python**: We follow [PEP 8](https://peps.python.org/pep-0008/). 
- **JavaScript/React**: verification of linting rules is recommended via `npm run lint`.

## Pull Request Process

1.  Fork the repository and create your branch from `main`.
2.  If you've added code that should be tested, add tests.
3.  Ensure the test suite passes.
4.  Make sure your code lints.
5.  Issue that pull request!

## Reporting Bugs

Please use the [GitHub Issues](https://github.com/4nilsj/apscan/issues) page to report bugs. Include:
- A clear description of the issue.
- Steps to reproduce.
- Expected vs. actual behavior.
- Logs or screenshots if applicable.
