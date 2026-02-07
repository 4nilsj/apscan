from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class CORSRule(ScannerRule):
    id = "API8-CORS-001"
    name = "CORS Misconfiguration"
    
    EVIL_ORIGIN = "http://evil.com"

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        url = context.target_url.rstrip('/') + endpoint.path
        
        headers = {
            "Origin": self.EVIL_ORIGIN
        }
        # Update with auth headers to verify if credentials are allowed with evil origin
        headers.update(context.auth_headers)
        
        req = ScanRequest(method=endpoint.method, url=url, headers=headers)
        resp = await context.http_client.send(req)
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        # Check 1: Reflected Origin with Credentials
        if acao == self.EVIL_ORIGIN and acac == "true":
             findings.append(Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.HIGH,
                description=f"Endpoint allows Cross-Origin requests from arbitrary origins ({self.EVIL_ORIGIN}) with credentials.",
                impact="Attackers can steal data (CSRF/Data Exfiltration) from authenticated users.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Sent Origin: {self.EVIL_ORIGIN}\nReceived Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                recommendation="Do not blindly reflect the Origin header. Use a whitelist of trusted domains."
            ))
            
        # Check 2: Wildcard Origin (Generic)
        elif acao == "*":
             # If endpoint is public, this might be OK, but if it expects Auth, it's bad practice
             # though browsers block * + credentials.
             pass

        return findings
