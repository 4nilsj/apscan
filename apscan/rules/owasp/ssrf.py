from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class SSRFRule(ScannerRule):
    id = "API7-SSRF"
    name = "Server Side Request Forgery (SSRF)"
    
    PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/" # AWS Metadata
    ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        # Target parameters that look like URLs
        url_params = [p['name'] for p in endpoint.parameters if 'url' in p['name'].lower() or 'uri' in p['name'].lower() or 'hook' in p['name'].lower()]
        
        if not url_params:
            # Try generic fuzzing if no semantic match? 
            # safe mode: only if param name suggests URL
            return []

        base_url = context.target_url.rstrip('/') + endpoint.path
        
        for param in url_params:
            for payload in self.PAYLOADS:
                # Assuming query param for now
                params = {param: payload}
                headers = {}
                headers.update(context.auth_headers)
                
                req = ScanRequest(method=endpoint.method, url=base_url, params=params, headers=headers)
                resp = await context.http_client.send(req)
                
                # Detection: 
                # 1. High latency (timeout checking logic needed, maybe check elapsed_time > 2s)
                # 2. Content reflection (e.g. "root:x:0:0" from /etc/passwd)
                
                is_vuln = False
                evidence = ""
                
                if "root:x:0:0" in resp.body:
                    is_vuln = True
                    evidence = "LFI/SSRF confirmed: /etc/passwd content found."
                elif "ami-id" in resp.body: # AWS
                    is_vuln = True
                    evidence = "SSRF confirmed: AWS Metadata exposed."
                elif resp.elapsed_time > 2.0 and resp.status_code == 200:
                    # Heuristic: Connection to 127.0.0.1 often works instantly OR timeouts depend on firewall
                    # This is weak evidence but worth noting as warning
                    pass 
                    
                if is_vuln:
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=self.name,
                        severity=Severity.CRITICAL,
                        description=f"Endpoint is vulnerable to SSRF via '{param}'.",
                        impact="Internal network scanning, cloud metadata theft, LFI.",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence=evidence,
                        recommendation="Validate and allowlist URLs provided by users."
                    ))
                    break # Stop payloads for this param
                    
        return findings
