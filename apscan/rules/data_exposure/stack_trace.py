from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod, ScanRequest
import re

class StackTraceRule(ScannerRule):
    @property
    def id(self) -> str:
        return "STACK_TRACE"

    @property
    def name(self) -> str:
        return "Stack Trace Leak"

    def __init__(self):
        self.severity = Severity.MEDIUM
        self.description = "The application leaks verbose stack traces in error responses, exposing internal details."
        self.patterns = [
            r"Traceback \(most recent call last\):", # Python
            r"at java\.lang\.", # Java
            r"at .*?\(.*?\.java:\d+\)", # Java stack style
            r"/node_modules/", # Node
            r"SyntaxError: .*? in .*", # JS
            r"SQLSTATE\[\d+\]:" # PHP/SQL
        ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Trigger an error.
        # 1. Send malformed JSON if POST/PUT
        # 2. Send invalid types in params
        
        url = context.target_url.rstrip('/') + endpoint.path
        
        # Method 1: Malformed JSON body
        if endpoint.method in [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH]:
            req = ScanRequest(
                method=endpoint.method, 
                url=url, 
                headers={"Content-Type": "application/json"},
                data="{ invalid json " # Malformed
            )
            res = await context.http_client.send(req)
            await self._check_response(res, endpoint, findings)
            
        # Method 2: Array in query param (often causes 500 in weak frameworks)
        # Scan even for GET
        params = {p['name']: ["invalid", "types"] for p in endpoint.parameters}
        req = ScanRequest(method=endpoint.method, url=url, params=params)
        res = await context.http_client.send(req)
        await self._check_response(res, endpoint, findings, "Invalid Parameter Types")

        return findings

    async def _check_response(self, res, endpoint, findings, trigger="Malformed Request"):
        # Check 500s AND 400s (some frameworks leak traces in validation errors)
        if res.status_code >= 400:
            for pattern in self.patterns:
                if re.search(pattern, res.body, re.IGNORECASE):
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=self.name,
                        severity=Severity.MEDIUM,
                        description=f"Stack trace leaked in {res.status_code} response.",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence=f"Matched pattern: {pattern}\nResponse snippet: {res.body[:200]}...",
                        recommendation="Disable verbose error messages in production.",
                        response_details={"status": res.status_code, "body": res.body[:500]}
                    ))
                    break
