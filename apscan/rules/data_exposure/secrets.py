from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import APIEndpoint, ScanContext, Vulnerability, Severity, ScanRequest
import re

class SecretsExposureRule(ScannerRule):
    @property
    def id(self) -> str:
        return "SECRETS_EXPOSURE"

    @property
    def name(self) -> str:
        return "Hardcoded Secrets / Keys Exposure"

    def __init__(self):
        self.severity = Severity.CRITICAL
        self.description = "The API response potentially exposes sensitive API keys, tokens, or credentials."
        # Expanded Regex Patterns for secrets
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Google OAuth": r"ya29\.[0-9A-Za-z_-]+",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
            "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
            "Generic Private Key": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
            "Generic API Key (Potential)": r"(?i)(api_key|access_token|secret_key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{32,})['\"]?"
        }

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Send a standard request to the endpoint
        url = context.target_url.rstrip('/') + endpoint.path
        
        # If parameters exist, add dummy values to ensure we get a response
        params = {p['name']: "test" for p in endpoint.parameters if p['in'] == 'query'}
        
        req = ScanRequest(method=endpoint.method, url=url, params=params)
        
        # Send Request
        try:
            res = await context.http_client.send(req)
        except Exception:
            # If request fails, we can't analyze the body
            return []
        
        if not res.body:
            return []

        # Analyze Response Body
        for secret_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, res.body)
            for match in matches:
                # Capture the full match or specific group if defined
                evidence_text = match.group(0)
                if len(evidence_text) > 50:
                    evidence_text = evidence_text[:50] + "..."

                findings.append(Vulnerability(
                    rule_id=self.id,
                    name=f"{secret_type} Exposure",
                    severity=Severity.CRITICAL,
                    description=f"Response contains a potential {secret_type}.",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence=f"Matched pattern: {evidence_text}",
                    recommendation="Rotate the exposed key immediately and remove it from the code/response."
                ))
        
        return findings
