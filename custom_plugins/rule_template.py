from typing import List, Optional
from apscan.core.rule import ScannerRule
from apscan.core.context import APIEndpoint, ScanContext, Vulnerability, Severity, ScanRequest, HttpMethod

class CustomRuleTemplate(ScannerRule):
    """
    Template for creating custom security rules for APScan.
    
    Instructions:
    1. Rename the class to something descriptive (e.g., CheckAuthHeader).
    2. Set a unique `id` for your rule.
    3. Implement the `run` method to perform your check.
    """
    
    # [REQUIRED] Unique Identifier for the rule
    id = "custom-001" 
    
    # [REQUIRED] Human-readable name
    name = "Template Rule Name"
    
    # [OPTIONAL] Default severity
    severity = Severity.MEDIUM

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        """
        Execute the rule against a specific endpoint.
        
        Args:
            endpoint: The API endpoint being scanned (method, path, etc.)
            context: Shared context containing HTTP client, variables, etc.
            
        Returns:
            List[Vulnerability]: A list of findings, or empty list if safe.
        """
        findings = []
        
        # Example Logic: Build a request
        target_url = context.target_url.rstrip('/') + endpoint.path
        
        # You can use context.http_client to make requests
        # request = ScanRequest(method=endpoint.method, url=target_url)
        # response = await context.http_client.send(request)
        
        # Example Check: Verify something in response
        # if response.status_code == 200 and "sensitive_data" in response.body:
        #     findings.append(Vulnerability(
        #         rule_id=self.id,
        #         name=self.name,
        #         severity=Severity.HIGH,
        #         description=f"Endpoint {endpoint.path} exposes sensitive data.",
        #         impact="Data leakage.",
        #         endpoint=endpoint.path,
        #         method=endpoint.method,
        #         evidence=f"Found 'sensitive_data' in response body.",
        #         recommendation="Ensure sensitive data is masked or removed."
        #     ))
            
        return findings
