# APScan Architecture

APScan is a modular API security scanner designed for extensibility and integration into modern CI/CD pipelines. It follows a client-server architecture with a clear separation between the scanning engine, the rules, and the reporting interface.

## System Overview

```mermaid
graph TD
    Client[Web UI / CLI] -->|API / Commands| Server[APScan Server]
    Server -->|Orchestrates| Engine[Scanning Engine]
    Engine -->|Loads| Discovery[Discovery Module]
    Engine -->|Executes| Rules[Rule Engine]
    Rules -->|Uses| Context[Scan Context]
    Rules -->|Generates| Findings[Vulnerabilities]
    Engine -->|Stores| DB[(Database)]
    Engine -->|Generates| Reports[Reports (HTML/JSON)]
```

## Core Components

### 1. Server (`apscan/server`)
The entry point for the Web UI. It's a **FastAPI** application that provides endpoints for:
- Managing scan targets
- Triggering scans
- Retrieving results and reports
- Managing workflows

### 2. Scanning Engine (`apscan/core`)
The heart of the application.
- **`Orchestrator`**: Coordinates the entire scan process. It initializes the context, loads the discovery module, runs the rules, and aggregates results.
- **`Context`**: specific object passed to every rule. It holds the `HTTPClient`, target information, authentication tokens, and shared state.

### 3. Discovery Module (`apscan/discovery`)
Responsible for finding API endpoints to scan.
- **`OpenAPIParser`**: Parses Swagger/OpenAPI specifications.
- **`GraphQLParser`**: Introspects GraphQL endpoints.
- **`HARLoader`**: Loads endpoints from HTTP Archive (HAR) files.

### 4. Rule Engine (`apscan/rule_engine` & `apscan/rules`)
The logic for security checks.
- **`ScannerRule`**: The base class for all rules.
- **`RuleLoader`**: Dynamically loads rules from the `apscan/rules` directory and custom plugin directories.
- **Categories**: Rules are organized by category (e.g., `auth`, `bola`, `injection`, `owasp`).

### 5. AI Integration (`apscan/ai`)
Optional module for using LLMs (Gemini, OpenAI) to:
- Analyze complex findings.
- Generate remediation advice.
- Reduce false positives.

## Directory Structure

| Directory | Description |
|-----------|-------------|
| `apscan/core` | Core logic (Orchestration, Context) |
| `apscan/server` | FastAPI backend |
| `apscan/rules` | Built-in security rules |
| `apscan/discovery` | Endpoint discovery modules |
| `apscan/reporting` | Report generators (HTML, JSON, PDF) |
| `web/` | React/Vite Frontend |
| `custom_plugins/` | User-defined rules |

## Extending APScan

Developers can extend APScan by adding new rules in `custom_plugins/`. See `custom_plugins/rule_template.py` for details.
