from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class NoSQLInjectionRule(ScannerRule):
    id = "INJ-005"
    name = "NoSQL Injection"
    
    # Logic: Inject objects instead of strings
    # Logic: Inject objects instead of strings
    PAYLOADS = [
        {"$ne": None},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$where": "return true"},
        {"$where": "sleep(100)"}, # Time-based
        {"$ne": "invalid_value_likely"},
    ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        if endpoint.parameters:
            for param in endpoint.parameters:
                p_loc = param.get('in', 'query')
                # NoSQLi is mostly relevant for JSON bodies
                if p_loc == 'body':
                     findings.extend(await self._test_param(endpoint, context, param['name'], p_loc, endpoint.parameters))
        return findings

    async def _test_param(self, endpoint, context, param_name, param_loc, all_params):
        findings = []
        base_url = context.target_url.rstrip('/') + endpoint.path
        
        base_body = {}
        if all_params:
            for p in all_params:
                 if p.get('in') == param_loc:
                     schema = p.get('schema', {})
                     base_body[p['name']] = schema.get('default', 'test')

        # Baseline request
        # TODO: Ideally we compare against baseline.
        # For now, we inject and check if we get a suspicious number of results or specific errors.
        
        for payload_val in self.PAYLOADS:
            import copy
            json_body = copy.deepcopy(base_body)
            # Injecting object where string expected
            json_body[param_name] = payload_val
            
            headers = {}
            headers.update(context.auth_headers)
            
            req = ScanRequest(
                method=endpoint.method,
                url=base_url,
                json_body=json_body,
                headers=headers
            )
            
            resp = await context.http_client.send(req)
            
            # Detection:
            # 1. MongoDB Errors
            error_patterns = [r"MongoError", r"CastError", r"\$where", r"Object expected"]
            for err in error_patterns:
                if re.search(err, resp.body, re.IGNORECASE):
                     findings.append(self._create_finding(endpoint, str(payload_val), f"DB Error: {err}", resp.body))
                     return findings
            
            # 2. Logic Bypass (Return all documents) 
            # If response is large array but we expected 0 or 1.
            # Hard to know without baseline. 
            # Heuristic: If body contains many IDs or objects.
            if resp.status_code == 200 and len(resp.body) > 500 and "[" in resp.body:
                 # Weak heuristic, but maybe useful for flag
                 pass 

        return findings

    def _create_finding(self, endpoint, payload, match, body):
        return Vulnerability(
            rule_id=self.id,
            name=self.name,
            severity=Severity.HIGH,
            description=f"NoSQL Injection detected. Database error returned.",
            impact="Data leakage, Authentication Bypass in NoSQL DBs.",
            endpoint=endpoint.path,
            recommendation="Sanitize input, avoid passing user input directly to MongoDB query ops.",
            method=endpoint.method,
            evidence=f"Payload: {payload}\nMatched: {match}\nResponse Snippet: {body[:200]}"
        )
