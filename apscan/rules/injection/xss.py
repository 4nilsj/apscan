from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule
from apscan.utils.curl_gen import generate_curl_command

class XSSReflectedRule(ScannerRule):
    id = "INJ-XSS-001"
    name = "Reflected XSS"
    
    PAYLOADS = [
        "<script>alert('APScan')</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
    ]
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        if endpoint.parameters:
            for param in endpoint.parameters:
                if param['in'] == 'query':
                    findings.extend(await self._test_param(endpoint, context, param['name']))
        return findings

    async def _test_param(self, endpoint, context, param_name):
        findings = []
        base_url = context.target_url.rstrip('/') + endpoint.path
        
        for payload in self.PAYLOADS:
            params = {param_name: payload}
            headers = {}
            headers.update(context.auth_headers)
            
            req = ScanRequest(
                method=endpoint.method,
                url=base_url,
                params=params, 
                headers=headers
            )
            
            resp = await context.http_client.send(req)
            
            # Check if payload is reflected in body WITHOUT encoding
            if payload in resp.body:
                 findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    severity=Severity.HIGH,
                    description=f"Endpoint reflects user input without encoding (Reflected XSS).",
                    impact="Attackers can execute malicious scripts in user's browser.",
                    endpoint=endpoint.path,
                    recommendation="Context-aware output encoding (e.g. HTML entity encoding).",
                    method=endpoint.method,
                    evidence=f"Payload: {payload}\nResponse contains raw payload.",
                    reproduce_curl=generate_curl_command(req),
                    request_details={"url": req.url, "method": req.method, "headers": req.headers, "params": req.params},
                    response_details={"status_code": resp.status_code, "body_snippet": resp.body[:500]}
                ))
                # return findings # Return per param at least one to avoid spam
                 return findings
        return findings
