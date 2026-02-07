from typing import List
import asyncio
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class RateLimitRule(ScannerRule):
    id = "API4-RATE-LIMIT"
    name = "Lack of Rate Limiting"
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # Only test one endpoint to avoid spamming usage
        # Heuristic: Test "heavy" endpoints or just the first one we find.
        # MVP: Test ALL, but let executor handle concurrency. 
        # WARNING: This effectively DoSes the target if concurrency is high.
        # We should be careful. Let's send 10 reqs.
        
        url = context.target_url.rstrip('/') + endpoint.path
        headers = {}
        headers.update(context.auth_headers)
        
        req = ScanRequest(method=endpoint.method, url=url, headers=headers)
        
        # Send 10 requests rapidly
        coros = [context.http_client.send(req) for _ in range(10)]
        responses = await asyncio.gather(*coros)
        
        # Check for 429
        for r in responses:
            if r.status_code == 429:
                # Rate limit working!
                return []
                
        # Check headers in LAST response
        last_resp = responses[-1]
        rl_headers = [k for k in last_resp.headers.keys() if 'ratelimit' in k.lower()]
        
        if not rl_headers and last_resp.status_code < 400:
             return [Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity.LOW,
                description="Endpoint does not appear to enforce rate limiting (no 429s or headers observed).",
                impact="Susceptible to Denial of Service (DoS) or Brute Force.",
                endpoint=endpoint.path, 
                method=endpoint.method,
                evidence="Sent 10 requests, all successful, no X-RateLimit headers.",
                recommendation="Implement rate limiting middleware (e.g. 100/minute)."
            )]
            
        return []
