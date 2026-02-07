# APScan Troubleshooting Guide

This guide addresses common issues you might encounter while installing or running APScan.

## Installation Issues

### `ModuleNotFoundError: No module named 'apscan'`
**Cause**: The package hasn't been installed in the current environment.
**Solution**:
1.  Ensure your virtual environment is activated: `source .venv/bin/activate` or `.venv\Scripts\activate`
2.  Install the package in editable mode: `pip install -e .`

### `npm install` fails
**Cause**: Outdated Node.js version or network issues.
**Solution**:
1.  Check Node.js version (must be >= 18): `node -v`
2.  Delete `node_modules` and `package-lock.json` and try again:
    ```bash
    rm -rf node_modules package-lock.json
    npm install
    ```

## Runtime Issues

### Server fails to start (Port in use)
**Error**: `[Errno 48] Address already in use`
**Cause**: Another process is using port 8083 (backend) or 5175 (frontend).
**Solution**:
- **Backend**: Specify a different port:
  ```bash
  python -m uvicorn apscan.server.main:app --port 9000
  ```
- **Frontend**: Vite will automatically try the next available port (e.g., 5176). Check the terminal output for the correct URL.

### Database is locked
**Error**: `sqlite3.OperationalError: database is locked`
**Cause**: Multiple processes are trying to write to the SQLite database simultaneously.
**Solution**:
1.  Stop all running instances of the backend.
2.  Restart a single instance.
3.  Ensure `greenlet` is installed (`pip install greenlet`) as it's required for async SQLAlchemy with SQLite.

## Feature-Specific Issues

### PDF Report Generation Fails
**Error**: `Error generating PDF` or blank PDF.
**Cause**: Missing system dependencies for `xhtml2pdf`.
**Solution**:
- Ensure all Python dependencies are installed.
- Ensure all Python dependencies are installed.
- Check logs for specific missing libraries.

### `OSError: no library called "cairo" was found`
**Cause**: The system is missing the `cairo` graphics library required for PDF generation.
**Solution**:
- **macOS**: `brew install cairo pkg-config`
- **Ubuntu**: `sudo apt-get install libcairo2-dev`
- **Windows**: Install GTK3 runtime or use `pip install pipwin && pipwin install cairocffi`

### AI Analysis Not Working
**Error**: "AI Analysis Unavailable: Dependency missing." or API errors.
**Cause**: 
- `google-generativeai` or `openai` packages not installed.
- Invalid API keys.
**Solution**:
1.  Install optional dependencies if needed: `pip install google-generativeai openai`
2.  Check your environment variables or config for valid API keys.
