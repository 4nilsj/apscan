from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class MassAssignmentRule(ScannerRule):
    id = "MASS-ASSIGN"
    name = "Mass Assignment"
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        if endpoint.method not in [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH]:
            return []

        # Payload to test
        # Try to inject admin-like properties
        payload = '{"role": "admin", "is_admin": true, "balance": 999999}'
        
        # We need a valid URL. If paths have params, we need to fill them.
        # MVP: Skip paths with params for Mass Assign (complexity high), or fuzz simplisticly.
        if "{" in endpoint.path:
            return [] # Skip parametrized paths for simplicity
            
        url = context.target_url.rstrip('/') + endpoint.path
        
        headers = {"Content-Type": "application/json"}
        headers.update(context.auth_headers)

        req = ScanRequest(method=endpoint.method, url=url, headers=headers, body=payload)
        resp = await context.http_client.send(req)
        
        # If response *reflects* our injected keys, it's suspicious.
        findings = []
        lower_body = resp.body.lower()
        if resp.status_code in [200, 201] and ("is_admin" in lower_body or "role" in lower_body):
             findings.append(Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.MEDIUM,
                description="Endpoint accepts and reflects sensitive fields (Mass Assignment).",
                impact="Attackers might elevate privileges by overwriting protected fields.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Injected 'role': 'admin' and found reflection in response body.",
                recommendation="Use a strict allowlist (DTO) for input binding."
            ))
            
        return findings
