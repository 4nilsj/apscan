from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import APIEndpoint, ScanContext, Vulnerability, Severity, ScanRequest, HttpMethod

class DependencyCheckRule(ScannerRule):
    @property
    def id(self) -> str:
        return "DEPENDENCY_CHECK"

    @property
    def name(self) -> str:
        return "Dependency & Configuration Exposure"

    def __init__(self):
        self.severity = Severity.MEDIUM
        self.description = "Identifies potential dependency vulnerabilities via exposed config files or headers."
        self.config_files = [
            "/package.json",
            "/package-lock.json",
            "/requirements.txt",
            "/Pipfile",
            "/composer.json",
            "/Gemfile",
            "/pom.xml",
            "/build.gradle"
        ]
        self.version_headers = [
            "X-Powered-By",
            "X-AspNet-Version",
            "X-Runtime",
            "Server"
        ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []

        # 1. Check Response Headers of the current endpoint
        # We need a response from the current endpoint first
        url = context.target_url.rstrip('/') + endpoint.path
        req = ScanRequest(method=endpoint.method, url=url)
        try:
            res = await context.http_client.send(req)
            for header in self.version_headers:
                if header in res.headers:
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=f"Leaked Version Header: {header}",
                        severity=Severity.LOW,
                        description=f"The server exposes software version information via the {header} header.",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence=f"{header}: {res.headers[header]}",
                        recommendation="Configure the server to suppress version headers."
                    ))
        except Exception:
            pass # Continue to file checks

        # 2. Check for Exposed Config Files (Only run once per base URL ideally, but simplified here)
        # We'll use a heuristic: only run if we satisfy a condition (e.g. root path or specific trigger)
        # For now, we'll try to check relative to the current path if strictly necessary, 
        # BUT standard practice is checking from the root.
        
        # To avoid spamming, we could use a context variable 'checked_dependencies'. 
        # Assuming context isn't persistent across rule instantiations in a way that's easy to track yet.
        # We will check relative to the *root* of the target URL.
        
        # This part should ideally be in a "Discovery" phase or run once. 
        # We'll implement it here but it might be redundant if multiple endpoints scanned.
        # Check if the endpoint path is root-ish to minimize redundancy
        if endpoint.path == "/" or endpoint.path == "/health": 
             base_url = context.target_url.rstrip('/')
             for config_file in self.config_files:
                file_url = base_url + config_file
                file_req = ScanRequest(method=HttpMethod.GET, url=file_url)
                try:
                    file_res = await context.http_client.send(file_req)
                    if file_res.status_code == 200 and len(file_res.body) > 0:
                        # Basic validation content check
                        if "{" in file_res.body or "dependencies" in file_res.body or "require" in file_res.body:
                            findings.append(Vulnerability(
                                rule_id=self.id,
                                name=f"Exposed Configuration File: {config_file}",
                                severity=Severity.HIGH,
                                description=f"The file {config_file} is publicly accessible.",
                                endpoint=config_file,
                                method="GET",
                                evidence=f"Accessed {file_url} successfully.",
                                recommendation="Configure the web server to deny access to configuration files."
                            ))
                except Exception:
                    continue

        return findings
