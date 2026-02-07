from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod, ScanRequest

class UnsafeMethodsRule(ScannerRule):
    @property
    def id(self) -> str:
        return "UNSAFE_METHODS"

    @property
    def name(self) -> str:
        return "Unsafe HTTP Methods"

    def __init__(self):
        self.severity = Severity.LOW
        self.description = "The application supports unsafe HTTP methods like TRACE or TRACK."
        self.unsafe_methods = [HttpMethod.TRACE, HttpMethod.TRACK, HttpMethod.CONNECT]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        url = context.target_url.rstrip('/') + endpoint.path

        for method in self.unsafe_methods:
            req = ScanRequest(method=method, url=url)
            res = await context.http_client.send(req)
            
            # If 200 OK or reflected content, it's enabled.
            # 405 Method Not Allowed or 501 Not Implemented is good.
            # 403 Forbidden is also usually fine.
            
            is_unsafe = False
            evidence = ""
            
            if res.status_code == 200:
                is_unsafe = True
                evidence = f"Received 200 OK for {method.value}"
                
                # Special check for TRACE reflection
                if method == HttpMethod.TRACE and req.headers.get("User-Agent", "") in res.body:
                     evidence += " (Headers reflected in body - Cross Site Tracing risk)"
                     
            if is_unsafe:
                findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    severity=self.severity,
                    description=f"Method {method.value} is enabled.",
                    endpoint=endpoint.path,
                    method=method,
                    evidence=evidence,
                    recommendation=f"Disable the {method.value} method in server configuration.",
                    reproduce_curl=f"curl -X {method.value} {url} -I"
                ))

        return findings
