# APScan Usage Guide

This guide covers how to use APScan's Web UI and CLI to secure your APIs.

## 🖥️ Web User Interface

The Web UI is the easiest way to interact with APScan. It provides a visual dashboard for configuring scans, managing rules, and analyzing results.

### 1. Starting the Application
Ensure both backend and frontend are running (see [INSTALL.md](INSTALL.md)).
- Open your browser to **http://localhost:5175**.

### 2. Configuring a Scan
On the **Config** tab, choose your input method:

- **OpenAPI**: Enter the URL of your Swagger/OpenAPI specification (e.g., `http://localhost:8000/openapi.json`). APScan will automatically discover all endpoints.
- **cURL**: Paste a raw cURL command. APScan will parse the method, headers, and body to scan that specific request.
- **HAR**: Upload a `.har` file (HTTP Archive) exported from browser DevTools to scan a recorded session.
- **Workflow**: (Advanced) Use the visual builder to define a multi-step attack flow.

**Optional Settings**:
- **GraphQL**: Enable introspection query scanning.
- **AI Triage**: Select an AI provider (Gemini, OpenAI) to analyze findings for false positives.

Click **Initiate Scan Sequence** to start.

### 3. Using the No-Code Rule Builder
Create custom security checks without writing code.

1.  Navigate to the **Rules Engine** tab.
2.  Click **Create New Rule**.
3.  **Rule Details**: Give your rule a name (e.g., "Check Internal Error") and severity.
4.  **Target**: Define where the rule runs.
    - *Method*: GET, POST, etc.
    - *Path*: Use Regex (e.g., `/api/admin/.*`) to match specific endpoints.
5.  **Match Conditions**: Define what triggers a finding.
    - *Status Code*: e.g., `500`.
    - *Body Text*: e.g., `root:x:0:0`.
    - *Body Regex*: e.g., `(?i)password\s*=`.
    - *Headers*: e.g., `Server: Apache`.
6.  Click **Save Rule**. It will be active for the next scan.

### 4. Analyzing Results
Once a scan completes, you'll see the **Results** dashboard.

- **Severity Cards**: Quick summary of Critical, High, Medium, and Low findings.
- **Vulnerability Feed**: Detailed list of issues. Click on a card to see:
    - **Description**: What went wrong.
    - **Evidence**: The raw data (headers, body) that triggered the rule.
    - **Remediation**: How to fix it.
    - **Reproduce**: A tailored `curl` command to verify the vulnerability yourself.

---

## 💻 CLI Usage

APScan is CI/CD ready. You can run scans directly from your terminal.

### Basic Scan
Scan an API using its OpenAPI definition:

```bash
apscan scan --target http://localhost:8000/openapi.json
```

### Scan with Custom Rules
Include your custom rule directory (including those created by the Rule Builder):

```bash
apscan scan \
  --target http://localhost:8000/openapi.json \
  --plugin-dir ./apscan/rules/custom
```

### CI/CD Integration
APScan returns a non-zero exit code if vulnerabilities are found, breaking the build.

**Output JSON Report**:
```bash
apscan scan --target ... --output report.json
```

**Fail only on High/Critical**:
(Pending implementation of severity thresholds in CLI - currently exits 1 on any finding).

---

## 🛡️ Security Features

### Secrets Scanning
APScan automatically checks responses for leaked secrets, including:
- AWS Access Keys
- Google API Keys
- Private Keys (RSA, DSA)
- Slack/Discord Tokens

*Severity: CRITICAL*

### Dependency Analysis
Checks for:
- Exposed configuration files (`package.json`, `requirements.txt`, `.env`).
- Leaked version information in headers (`X-Powered-By`, `Server`).

*Severity: HIGH (Files) / LOW (Headers)*
