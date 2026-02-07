# APScan - API Security Scanner

A modular, plug-and-play API security scanner designed for CI/CD and modern API ecosystems. Features a powerful backend analysis engine and a modern React-based UI.

## Features
- **Modular Architecture**: Core scanner decoupled from rules and discovery.
- **OpenAPI Support**: Auto-discovery of endpoints from Swagger/OpenAPI specs.
- **GraphQL Support**: Introspection and specific security checks.
- **Secrets Scanning**: Detects hardcoded keys, tokens, and credentials in responses.
- **Dependency Analysis**: Identifies exposed config files and potential dependency vulnerabilities.
- **No-Code Rule Builder**: visual "Drag-and-Drop" interface to create custom security rules without coding.
- **AI Triage**: Optional integration with LLMs (Gemini, OpenAI) for advanced finding analysis.
- **Modern UI**: Interactive dashboard for configuring scans and viewing results.
- **CI/CD Ready**: CLI-first design with JSON/SARIF reporting.

## Prerequisites
- **Python**: >= 3.10
- **Node.js**: >= 18 (for Web UI)

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.
See [USAGE.md](USAGE.md) for a comprehensive usage guide for the Web UI and CLI.

### Quick Start

1.  **Backend**:
    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install -e .
    ```

2.  **Frontend**:
    ```bash
    cd web
    npm install
    ```

## Running the Application

To use the full Web UI experience, you need to run both the backend server and the frontend development server.

### Start Backend Server

runs on **port 8083**.

```bash
# In project root
python -m uvicorn apscan.server.main:app --host 0.0.0.0 --port 8083 --reload
```

### Start Frontend UI

Runs on **port 5175**.

```bash
# In web/ directory
npm run dev
```

Open your browser to [http://localhost:5175](http://localhost:5175).

## CLI Usage

You can also run scans directly from the command line:

```bash
# Scan an OpenAPI endpoint
apscan scan --target http://localhost:8000/openapi.json

# Scan using a HAR file
apscan scan --har ./capture.har

# Scan a GraphQL endpoint
apscan scan --target http://localhost:8000/graphql --graphql
```

## Extending APScan (Custom Rules)

You can extend APScan capabilities by adding custom rules. Rules are Python classes that inherit from `ScannerRule`.

### 1. Create a Rule
Create a python file (e.g., `my_rules/custom_check.py`) with your rule logic.
You can find a well-documented template at `custom_plugins/rule_template.py`.

```python
from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import APIEndpoint, ScanContext, Vulnerability, Severity, ScanRequest

class MyCustomRule(ScannerRule):
    id = "CUST-001"
    name = "Custom Header Check"
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Build a request
        url = context.target_url.rstrip('/') + endpoint.path
        req = ScanRequest(method=endpoint.method, url=url)
        
        # Send request
        resp = await context.http_client.send(req)
        
        # Analyze response
        if "X-Required-Header" not in resp.headers:
            findings.append(Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.MEDIUM,
                description=f"Endpoint {endpoint.path} is missing X-Required-Header",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Headers received: {list(resp.headers.keys())}"
            ))
            
        return findings
```

### 2. Run with Custom Rules
Use the `--plugin-dir` argument to include your custom rules directory:

```bash
apscan scan --target http://localhost:8000/openapi.json --plugin-dir ./my_rules
```


## No-Code Rule Builder

APScan includes a powerful visual rule builder for creating custom security checks without writing any code.

1.  **Access**: Navigate to the "Rules Engine" tab in the Web UI.
2.  **Create**: Define rule metadata (Name, Severity), target (Method, Path Regex), and match conditions (Status Code, Body Text/Regex, Headers).
3.  **Deploy**: Save the rule, and it will be automatically picked up by the next scan.
4.  **Manage**: View, delete, and manage your custom rules directly from the dashboard.

## Workflow Automation

APScan supports YAML-based workflows for complex authentication flows or multi-step attacks. Use the visual builder in the Web UI to generate these.

## Troubleshooting

Encountering issues? Check out our [Troubleshooting Guide](TROUBLESHOOTING.md) for solutions to common problems.
