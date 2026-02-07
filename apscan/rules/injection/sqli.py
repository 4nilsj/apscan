from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class SQLInjectionRule(ScannerRule):
    id = "INJ-SQL-001"
    name = "SQL Injection (Error-Based)"
    
    # Common SQL Error patterns
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQLServer",
        r"OLE DB.* SQL Server",
        r"Unclosed quotation mark after the character string",
        r"OracleError",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
    ]

    PAYLOADS = [
        "'",
        "\"",
        "'--",
        "') OR '1'='1",
        "' OR 1=1 --",
        "1' OR '1'='1",
        # Union
        "' UNION SELECT 1, @@version --",
        # Time-based (Generic)
        "'; WAITFOR DELAY '0:0:5' --", 
        "'; SELECT pg_sleep(5) --",
    ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Test Parameters (Query, Body, FormData)
        if endpoint.parameters:
            for param in endpoint.parameters:
                p_loc = param.get('in', 'query')
                if p_loc in ['query', 'body', 'formData']:
                    findings.extend(await self._test_param(endpoint, context, param['name'], p_loc, endpoint.parameters))
        
        return findings

    async def _test_param(self, endpoint, context, param_name, param_loc='query', all_params=None):
        findings = []
        base_url = context.target_url.rstrip('/') + endpoint.path
        
        # Helper to construct base body/data
        base_body = {}
        if all_params:
            for p in all_params:
                 if p.get('in') == param_loc:
                     schema = p.get('schema', {})
                     base_body[p['name']] = schema.get('default', 'test')

        for payload in self.PAYLOADS:
            params = {}
            json_body = None
            data = None
            
            if param_loc == 'query':
                params = {param_name: payload}
            elif param_loc == 'body':
                import copy
                json_body = copy.deepcopy(base_body)
                json_body[param_name] = payload
            elif param_loc == 'formData':
                import copy
                data = copy.deepcopy(base_body)
                data[param_name] = payload
            
            headers = {}
            headers.update(context.auth_headers)
            
            req = ScanRequest(
                method=endpoint.method,
                url=base_url,
                params=params, 
                json_body=json_body,
                data=data,
                headers=headers
            )
            
            # In context/http_client we might need to handle params merging if logic separates it.
            # Assuming http_client.send handles req.params
            
            resp = await context.http_client.send(req)
            
            # Debug Print removed
            
            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, resp.body, re.IGNORECASE):
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=self.name,
                        severity=Severity.CRITICAL, # SQLi is usually Critical
                        description=f"Endpoint returns database error messages when injecting '{payload}'.",
                        impact="Full database compromise, data leakage, data loss.",
                        endpoint=endpoint.path,
                        recommendation="Use parametrized queries (Prepared Statements) for all DB access.",
                        method=endpoint.method,
                        evidence=f"Payload: {payload}\nMatched Error: {pattern}\nResponse Snippet: {resp.body[:200]}"
                    ))
                    # Return immediately per param per payload to avoid dups
                    return findings
        return findings
