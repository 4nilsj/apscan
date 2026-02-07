from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod, ScanRequest

class PrototypePollutionRule(ScannerRule):
    @property
    def id(self) -> str:
        return "PROTO_POLLUTION"

    @property
    def name(self) -> str:
        return "Prototype Pollution"

    def __init__(self):
        self.severity = Severity.HIGH
        self.description = "The API is vulnerable to JavaScript Prototype Pollution, allowing attackers to modify object prototypes."
        self.payload = {
            "__proto__": {
                "polluted": "true"
            },
            "constructor": {
                "prototype": {
                    "polluted": "true"
                }
            }
        }

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Only relevant for POST/PUT with JSON
        if endpoint.method not in [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH]:
            return []

        url = context.target_url.rstrip('/') + endpoint.path
        
        # Inject Payload
        req = ScanRequest(
            method=endpoint.method,
            url=url,
            json_body=self.payload,
            headers={"Content-Type": "application/json"}
        )
        
        res = await context.http_client.send(req)
        
        # Detection is tricky.
        # 1. Check if "polluted" is reflected in response keys (if server echoes back object)
        # 2. Check for specific errors if we broke something?
        # 3. Ideally we need a second request to check if "polluted" appears where it shouldn't.
        # For this MVP, we check reflection in keys.
        
        if '"polluted": "true"' in res.body:
             # Basic reflection check - not definitive proof of pollution but strong indicator of unsafe merge
             # We assume if the server accepted it and echoed it back, it might have merged it.
             findings.append(Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=self.severity,
                description="Server accepted and reflected __proto__ payload. This suggests potential for Prototype Pollution.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence="Response contains \"polluted\": \"true\" after injection.",
                recommendation="Use safe deep-merge functions prevents __proto__ key modifications.",
                reproduce_curl=f"curl -X POST {url} -H 'Content-Type: application/json' -d '{str(self.payload)}'"
            ))

        return findings
