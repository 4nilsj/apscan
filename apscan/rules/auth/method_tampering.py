from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class MethodTamperingRule(ScannerRule):
    id = "AUTH-002"
    name = "HTTP Verb Tampering"
    
    # Methods to test for bypass
    TEST_METHODS = ["HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "TRACK"]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        url = context.target_url.rstrip('/') + endpoint.path
        
        # 1. Establish Baseline: Request WITHOUT auth using original method
        req_base = ScanRequest(method=endpoint.method, url=url) # No headers = No Auth
        resp_base = await context.http_client.send(req_base)
        
        # If the endpoint assumes public access (200 OK), we can't test for bypass here easily 
        # unless checking for hidden admin functionality.
        if resp_base.status_code not in [401, 403]:
            return []

        # 2. Test Tampered Methods
        # Logic: If GET /admin -> 403
        # Try HEAD /admin. If 200 OK -> Bypass?
        # Note: HEAD 200 OK just means "Resource exists" usually. 
        # But if the auth filter only checks "GET", then "HEAD" bypassing it reveals presence.
        # More critical: If we can DELETE /users/1 via POST/PUT if GET is blocked? 
        # (This is more BFLA/Authz).
        # We focus on "Auth Bypass via Method".
        
        # Test 1: HEAD Bypass (Common)
        req_head = ScanRequest(method=HttpMethod.HEAD, url=url)
        resp_head = await context.http_client.send(req_head)
        
        if resp_head.status_code == 200:
             # HEAD return 200 while GET returned 401/403
             findings.append(Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.HIGH,
                description=f"Endpoint {endpoint.path} protects {endpoint.method.value} but allows HEAD requests without authentication.",
                impact="Attackers might map internal resources or bypass access controls.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Original {endpoint.method.value} -> {resp_base.status_code}\nHEAD -> {resp_head.status_code}",
                recommendation="Ensure authentication middleware verifies all HTTP methods, not just specific ones."
            ))
            
        return findings
