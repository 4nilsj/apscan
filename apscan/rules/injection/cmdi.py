from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class CommandInjectionRule(ScannerRule):
    id = "INJ-003"
    name = "Command Injection (CMDi)"
    
    PAYLOADS = [
        "; cat /etc/passwd",
        "| id",
        "$(whoami)",
        "& ping -c 1 127.0.0.1",
        "`id`",
        # Windows
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "| dir C:\\",
        # Separators
        "%0Acat /etc/passwd",
        "|| cat /etc/passwd",
        "&& cat /etc/passwd",
        # OOB/DNS (Simulated)
        "; nslookup 127.0.0.1",
    ]

    SIGNATURES = [
        r"root:x:0:0",
        r"uid=[0-9]+\(",
        r"gid=[0-9]+\(",
        r"ttl=[0-9]+",
        r"127\.0\.0\.1",
        r"Volume Serial Number", # Windows
        r"Microsoft Windows",
        r"drwx", # Linux ls -la
        r"drivers\\etc\\hosts",
        r"Server:", # nslookup
    ]

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        if endpoint.parameters:
            for param in endpoint.parameters:
                p_loc = param.get('in', 'query')
                if p_loc in ['query', 'body', 'formData']:
                    findings.extend(await self._test_param(endpoint, context, param['name'], p_loc, endpoint.parameters))
        return findings

    async def _test_param(self, endpoint, context, param_name, param_loc, all_params):
        findings = []
        base_url = context.target_url.rstrip('/') + endpoint.path
        
        # Base body construction
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
            
            resp = await context.http_client.send(req)
            
            for signature in self.SIGNATURES:
                if re.search(signature, resp.body):
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=self.name,
                        severity=Severity.CRITICAL,
                        description=f"Possible OS Command Injection detected using payload '{payload}'.",
                        impact="Remote Code Execution (RCE), Full System Compromise.",
                        endpoint=endpoint.path,
                        recommendation="Avoid system calls with user input. Use safe APIs or strictly validate input (allowlist).",
                        method=endpoint.method,
                        evidence=f"Payload: {payload}\nMatched Signature: {signature}\nResponse Snippet: {resp.body[:200]}"
                    ))
                    return findings
        return findings
