from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod

class OpenRedirectRule(ScannerRule):
    @property
    def id(self) -> str:
        return "OPEN_REDIRECT"

    @property
    def name(self) -> str:
        return "Open Redirect"

    def __init__(self):
        self.severity = Severity.MEDIUM
        self.description = "The API allows unvalidated redirects to external sites, which can be used for phishing attacks."
        self.payloads = [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "http:\evil.com"
        ]
        self.target_params = ["next", "url", "redirect", "redirect_to", "return_to", "dest", "destination"]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Only inject into relevant parameters
        target_params = [
            p_name for p_name, p_schema in self._get_flattened_params(endpoint).items()
            if any(tp in p_name.lower() for tp in self.target_params)
        ]

        if not target_params:
            return []

        for param_name in target_params:
            for payload in self.payloads:
                # Mutate request
                kwargs = self._create_request_kwargs(endpoint, context, {param_name: payload})
                
                # Send
                req = await self._send_request(context, endpoint.method, endpoint.path, **kwargs)
                
                # Check for redirect
                if 300 <= req.status_code < 400:
                    location = next((v for k, v in req.headers.items() if k.lower() == "location"), "")
                    
                    if "evil.com" in location:
                        findings.append(Vulnerability(
                            rule_id=self.id,
                            name=self.name,
                            severity=self.severity,
                            description=f"Parameter '{param_name}' reflects input in Location header, allowing open redirects.",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            evidence=f"Payload: {payload}\nLocation: {location}",
                            recommendation="Validate all redirect targets against a whitelist of allowed domains.",
                            reproduce_curl=f"curl -X {endpoint.method.value} '{context.target_url}{endpoint.path}?{param_name}={payload}' -I"
                        ))
                        break # One find per param is enough

        return findings

    def _get_flattened_params(self, endpoint):
        # Helper to get all param names
        params = {}
        for p in endpoint.parameters:
            params[p['name']] = p
        return params

    def _create_request_kwargs(self, endpoint, context, mutations):
        # Simplistic helper - ideally rely on Orchestrator or Generator
        # But here we implement basic construction for the rule
        params = {}
        for p in endpoint.parameters:
            name = p['name']
            if name in mutations:
                params[name] = mutations[name]
            else:
                params[name] = "test" # Default
        
        return {"params": params}

    async def _send_request(self, context, method, path, **kwargs):
        from apscan.core.context import ScanRequest
        url = context.target_url.rstrip('/') + path
        req = ScanRequest(method=method, url=url, **kwargs)
        return await context.http_client.send(req)
