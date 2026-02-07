from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod, ScanRequest
import re

class PIIExposureRule(ScannerRule):
    @property
    def id(self) -> str:
        return "PII_EXPOSURE"

    @property
    def name(self) -> str:
        return "Sensitive Data Exposure (PII)"

    def __init__(self):
        self.severity = Severity.HIGH
        self.description = "The API response contains sensitive PII or secrets (SSN, Email, Keys)."
        self.patterns = {
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "US SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----"
        }

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # We need to trigger the request first.
        # This rule is passive-ish: it analyzes the response.
        # Since we are in an active scan, we can just send a standard valid request (if we knew how)
        # Or rely on the fact that Orchestrator might call this after fuzzing?
        # Current architecture: Rule is responsible for sending requests.
        
        # Simple Check: Send a default request (no mutation)
        # TODO: Ideally assume Orchestrator provides a valid "baseline" request or response.
        # Here we just construct a basic one.
        
        kwargs = {"params": {p['name']: "test" for p in endpoint.parameters}}
        url = context.target_url.rstrip('/') + endpoint.path
        req = ScanRequest(method=endpoint.method, url=url, **kwargs)
        
        # Send Request
        res = await context.http_client.send(req)
        
        # Analyze Body
        for pii_type, pattern in self.patterns.items():
            matches = re.findall(pattern, res.body)
            if matches:
                 # Filter out false positives for CCs (Luhn) or common test emails
                 # For MVP, just report
                 if pii_type == "Credit Card":
                     # Simple logic to avoid phone numbers or longs: check if dashes used consistently
                     pass 

                 findings.append(Vulnerability(
                    rule_id=self.id,
                    name=pii_type + " Exposure",
                    severity=Severity.HIGH,
                    description=f"Response contains suspected {pii_type}.",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence=f"Matched pattern: {matches[0]}...",
                    recommendation="Ensure sensitive PII is masked or encrypted."
                ))

        return findings
