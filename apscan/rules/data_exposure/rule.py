from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class DataExposureRule(ScannerRule):
    id = "DATA-EXPOSURE"
    name = "Excessive Data Exposure"
    
    # Sensitive PII patterns
    PATTERNS = [
        r'"ssn"\s*:', 
        r'"social_security"\s*:',
        r'"password"\s*:', 
        r'"api_key"\s*:',
        r'"private_key"\s*:',
        r'"credit_card"\s*:',
        r'[0-9]{3}-[0-9]{2}-[0-9]{4}' # Simple SSN regex
    ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        if endpoint.method != HttpMethod.GET:
            return []

        # We assume regular scan hits this endpoint if it's parameter-less,
        # or we might need to fuzz params.
        # MVP: Scan only parameter-less GETs or rely on what we can reach.
        if "{" in endpoint.path:
            return [] 

        url = context.target_url.rstrip('/') + endpoint.path
        headers = {}
        headers.update(context.auth_headers)
        
        req = ScanRequest(method=endpoint.method, url=url, headers=headers)
        resp = await context.http_client.send(req)
        
        for pattern in self.PATTERNS:
            if re.search(pattern, resp.body, re.IGNORECASE):
                return [Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    severity=Severity.HIGH,
                    description=f"Endpoint exposes sensitive data matching pattern {pattern}.",
                    impact="Leakage of PII or credentials.",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence=f"Matched pattern: {pattern} in response.",
                    recommendation="Filter sensitive fields from the response DTO."
                )]

        return []
