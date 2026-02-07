# APScan Installation Guide

This guide provides step-by-step instructions for installing and setting up APScan on your local machine.

## Prerequisites

Before starting, ensure you have the following software installed:

- **Python**: Version 3.10 or higher.
  - Check version: `python --version`
- **Node.js**: Version 18 or higher (for the Web UI).
  - Check version: `node --version`
- **Git**: For cloning the repository.
  - Check version: `git --version`

## Step 1: Clone the Repository

First, get the code on your machine:

```bash
git clone https://github.com/4nilsj/apscan.git
cd apscan
```

## Step 2: Backend Setup

APScan's backend is built with Python and FastAPI. We recommend using a virtual environment to manage dependencies.

1.  **Create a virtual environment**:
    ```bash
    python -m venv .venv
    ```

2.  **Activate the virtual environment**:
    - **macOS/Linux**:
      ```bash
      source .venv/bin/activate
      ```
    - **Windows**:
      ```bash
      .venv\Scripts\activate
      ```

3.  **Install dependencies**:
    Install the package in editable mode along with its dependencies:
    ```bash
    pip install -e .
    ```
    *Note: If you encounter issues with async database operations, ensure `greenlet` is installed:*
    ```bash
    pip install greenlet
    ```

## Step 3: Frontend Setup

The frontend is a modern React application.

1.  **Navigate to the web directory**:
    ```bash
    cd web
    ```

2.  **Install dependencies**:
    ```bash
    npm install
    ```

## Step 4: Verify Installation

You can verify the installation by running the help command for the CLI:

```bash
# From the project root (ensure .venv is activated)
apscan --help
```

## Troubleshooting

### Port Conflicts
- The backend defaults to port `8083`. If this port is in use, the server will fail to start. You can change the port in the start command:
  ```bash
  python -m uvicorn apscan.server.main:app --host 0.0.0.0 --port 9000
  ```

### "apscan command not found"
- Ensure your virtual environment is activated (`source .venv/bin/activate`).
- Ensure you installed the package with `pip install -e .`. 
