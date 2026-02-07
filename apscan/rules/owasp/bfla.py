from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class BFLARule(ScannerRule):
    id = "API5-BFLA"
    name = "Broken Function Level Authorization"
    
    SENSITIVE_KEYWORDS = ["admin", "root", "system", "config", "settings", "users", "export", "backup"]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # Logic: If path contains sensitive keyword and is 200 OK with CURRENT credentials, warn user.
        # This assumes the scan is performed with a LOW PRIVILEGE user.
        
        path_lower = endpoint.path.lower()
        is_sensitive = any(kw in path_lower for kw in self.SENSITIVE_KEYWORDS)
        
        if not is_sensitive:
            return []
            
        # We need to test access. But Orchestrator has not "pre-tested" validity with provided auth.
        # We perform a request.
        
        url = context.target_url.rstrip('/') + endpoint.path
        headers = {}
        headers.update(context.auth_headers)
        
        req = ScanRequest(method=endpoint.method, url=url, headers=headers)
        resp = await context.http_client.send(req)
        
        if resp.status_code in [200, 201, 204]:
             return [Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.HIGH,
                description=f"Sensitive endpoint accessible by current user: {endpoint.path}",
                impact="Low-privileged users might perform administrative actions.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Matched keyword in path and received {resp.status_code}.",
                recommendation="Ensure ACLs deny access to this function for standard users."
            )]
            
        return []
