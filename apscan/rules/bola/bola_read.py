from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class BOLAReadRule(ScannerRule):
    id = "BOLA-READ"
    name = "Broken Object Level Authorization (Read)"
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        if endpoint.method != HttpMethod.GET:
            return []

        # Find ID parameters
        path_params = [p['name'] for p in endpoint.parameters if p['in'] == 'path']
        if not path_params:
            return []

        # Simple Heuristic: Assume parameter with 'id' in name is an ID.
        result = []
        for param in path_params:
            if 'id' in param.lower():
                # Attempt to access two different IDs
                # We authenticate using default headers (ScanContext has them merged if auth is set)
                # But to test BOLA, we need to be User A and access User B's resource.
                # MVP Limitation: We typically only have 1 auth token or 0.
                # If we have 1 token, we check if we can access ARBITRARY IDs.
                # If we get 200 OK for ID '1' and '2', it MIGHT be public data or BOLA.
                
                # Test ID 1
                resp1 = await self._test_id(endpoint, context, param, "1")
                # Test ID 1337 (Random ID)
                resp2 = await self._test_id(endpoint, context, param, "1337")

                if resp1.status_code == 200 and resp2.status_code == 200:
                   # If bodies are DIFFERENT but successful, likely BOLA.
                   # If bodies are IDENTICAL, might be returning static content or ignoring ID.
                   if resp1.body != resp2.body and abs(len(resp1.body) - len(resp2.body)) < len(resp1.body):
                       result.append(Vulnerability(
                           rule_id=self.id,
                           name=self.name,
                           severity=Severity.HIGH,
                           description=f"Endpoint accessible with multiple object IDs ({param}).",
                           impact="Attackers can access unauthorized data objects.",
                           endpoint=endpoint.path,
                           method=endpoint.method,
                           evidence=f"ID 1: 200 OK ({len(resp1.body)}b)\nID 1337: 200 OK ({len(resp2.body)}b)",
                           recommendation="Implement object-level ownership checks."
                       ))
        return result

    async def _test_id(self, endpoint, context, param_name, val):
        url = context.target_url.rstrip('/') + endpoint.path.replace(f"{{{param_name}}}", val)
        
        # Merge Auth Headers
        headers = {}
        headers.update(context.auth_headers)
        
        req = ScanRequest(method=endpoint.method, url=url, headers=headers)
        return await context.http_client.send(req)
