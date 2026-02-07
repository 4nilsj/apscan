from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class ShadowAPIRule(ScannerRule):
    id = "API9-INVENTORY"
    name = "Shadow/Zombie API Detection"
    
    COMMON_PREFIXES = ["/v1", "/v2", "/api/v1", "/api/v2", "/beta", "/test", "/internal", "/old"]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # This rule doesn't scan the *current* endpoint, but uses the Base URL 
        # to try and find OTHERS.
        # To avoid redundancy, we should run this ONCE per scan.
        # Hack for MVP: check if endpoint path is root or just probability 1/10?
        # Better: Implementation check
        
        # We will only run if endpoint path is the first one in list?
        # context.endpoints[0] == endpoint logic requires equality check.
        # Let's just run it for every endpoint but use a 'tested' set in context?
        # Context is shared but attributes need to be defined.
        
        # Simplified: Try to mutate the CURRENT endpoint's version if present.
        # e.g. /v1/users -> try /v2/users, /beta/users
        
        findings = []
        path = endpoint.path
        
        # Heuristic: look for /v[0-9]+/
        import re
        version_match = re.search(r"/(v\d+)/", path)
        
        if version_match:
            current_ver = version_match.group(1)
            # Try to guess other versions
            guesses = ["v1", "v2", "v3", "beta"]
            if current_ver in guesses:
                guesses.remove(current_ver)
            
            for guess in guesses:
                new_path = path.replace(current_ver, guess)
                url = context.target_url.rstrip('/') + new_path
                headers = {}
                headers.update(context.auth_headers)
                
                req = ScanRequest(method=endpoint.method, url=url, headers=headers)
                resp = await context.http_client.send(req)
                
                if resp.status_code == 200:
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=self.name,
                        severity=Severity.MEDIUM,
                        description=f"Endpoint version variant found: {new_path}",
                        impact="Old API versions (Zombie APIs) may have unpatched vulnerabilities.",
                        endpoint=new_path,
                        method=endpoint.method,
                        evidence=f"Accessing {new_path} returned 200 OK.",
                        recommendation="Disable old API versions and remove unused routes."
                    ))
        
        return findings
