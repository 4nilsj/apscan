from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext
from apscan.core.rule import ScannerRule
from apscan.core.request_engine import RequestFactory

class AuthBypassRule(ScannerRule):
    id = "AUTH-001"
    name = "Unauthenticated Access"
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # 1. Generate a request WITHOUT auth headers
        
        full_url = context.target_url.rstrip('/') + endpoint.path
        
        # Exclude common auth headers to properly test for bypass
        exclude = ["Authorization", "authorization", "X-API-Key", "x-api-key", "token", "access_token"]
        
        req = RequestFactory.create_request(endpoint, exclude_params=exclude)
        
        # Correctly construct full URL using the factory-generated path
        if not req.url.startswith("http"):
             req.url = context.target_url.rstrip('/') + req.url
        
        response = await context.http_client.send(req)
        
        if response.status_code == 200:
            # Found a potential issue
            return [Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.HIGH,
                description=f"Endpoint {endpoint.path} is accessible without authentication.",
                impact="Unauthorized actors can access sensitive data or perform actions.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence=f"Received 200 OK with body: {response.body[:200]}...",
                recommendation="Implement proper authentication middleware (e.g., OAuth2, API Key) for this endpoint."
            )]
            
        return []
