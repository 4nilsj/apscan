from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class SecurityHeadersRule(ScannerRule):
    id = "API8-MISCONFIG"
    name = "Missing Security Headers"
    
    REQUIRED_HEADERS = [
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy" 
        # API specific ones closer to API8
    ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # One check per scan usually implies checking global config, 
        # but usually headers are checked per response.
        
        url = context.target_url.rstrip('/') + endpoint.path
        headers = {}
        headers.update(context.auth_headers)
        
        req = ScanRequest(method=endpoint.method, url=url, headers=headers)
        resp = await context.http_client.send(req)
        
        missing = []
        for h in self.REQUIRED_HEADERS:
            # Case insensitive check
            if not any(k.lower() == h.lower() for k in resp.headers):
                missing.append(h)
                
        if missing and resp.status_code == 200:
             return [Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.LOW,
                description=f"Response missing security headers: {', '.join(missing)}.",
                impact="Reduced defense against XSS, clickjacking, and MITM.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Headers received: {list(resp.headers.keys())}",
                recommendation="Configure your web server/gateway to send standard security headers."
            )]
            
        return []
