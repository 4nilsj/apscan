from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class BOLAWriteRule(ScannerRule):
    id = "BOLA-WRITE"
    name = "Broken Object Level Authorization (Write)"
    
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        if endpoint.method not in [HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.PATCH]:
            return []

        path_params = [p['name'] for p in endpoint.parameters if p['in'] == 'path']
        if not path_params:
            return []

        result = []
        for param in path_params:
            if 'id' in param.lower():
                # DANGEROUS: Writing might corrupt data.
                # MVP Safe Mode: We shouldn't really delete stuff blindly.
                # But for PUT, we can try to send empty body or innocuous data?
                # For safety, maybe skip DELETE?
                if endpoint.method == HttpMethod.DELETE:
                    continue 
                    
                # Test ID 99999 (High ID likely non-existent, but if we get 200/201/202/204, it's weird)
                # Or 403 vs 404 check.
                resp = await self._test_id(endpoint, context, param, "99999")
                
                # If we get success on a random large ID, it implies weak checks or creation allowed.
                if resp.status_code in [200, 202, 204]:
                     result.append(Vulnerability(
                           rule_id=self.id,
                           name=self.name,
                           severity=Severity.HIGH,
                           description=f"Endpoint allows modification of arbitrary object IDs ({param}).",
                           impact="Attackers can modify or delete data they don't own.",
                           endpoint=endpoint.path,
                           method=endpoint.method,
                           evidence=f"ID 99999: Status {resp.status_code}",
                           recommendation="Verify user ownership before state-changing operations."
                       ))

        return result

    async def _test_id(self, endpoint, context, param_name, val):
        url = context.target_url.rstrip('/') + endpoint.path.replace(f"{{{param_name}}}", val)
        headers = {}
        headers.update(context.auth_headers)
        # Send empty JSON body
        req = ScanRequest(method=endpoint.method, url=url, headers=headers, body="{}")
        return await context.http_client.send(req)
