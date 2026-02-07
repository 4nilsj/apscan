import re
import copy
import json
from typing import List, Dict, Any, Optional
from apscan.core.context import ScanContext, ScanRequest, APIEndpoint, HttpMethod
from apscan.core.workflow import Workflow, WorkflowStep, Extraction
from apscan.utils.http import HTTPClient
from apscan.rule_engine.executor import RuleExecutor

class WorkflowExecutor:
    def __init__(self, context: ScanContext, rule_executor: Optional[RuleExecutor] = None):
        self.context = context
        self.rule_executor = rule_executor

    async def execute(self, workflow: Workflow):
        """
        Executes a workflow sequence.
        """
        print(f"[*] Starting Workflow: {workflow.name}")
        
        for step in workflow.steps:
            await self._execute_step(step)

    async def _execute_step(self, step: WorkflowStep):
        # 1. Substitute Variables
        path = self._substitute(step.path)
        body = self._substitute(step.body) if step.body else None
        headers = {k: self._substitute(v) for k, v in step.headers.items()}
        params = {k: self._substitute(v) for k, v in step.params.items()}
        files = {k: self._substitute(v) for k, v in step.files.items()} if step.files else None
        
        # 2. Build Request
        url = self.context.target_url.rstrip('/') + path
        
        # Merge Auth Headers if needed (or assume workflow handles it?)
        # Let's merge default auth headers unless overridden
        final_headers = copy.deepcopy(self.context.auth_headers)
        final_headers.update(headers)
        
        req = ScanRequest(
            method=HttpMethod(step.method.upper()),
            url=url,
            headers=final_headers,
            params=params,
            json_body=body if isinstance(body, (dict, list)) else None,
            data=body if isinstance(body, str) else None,
            files=files
        )
        
        print(f"    -> Step {step.id}: {req.method} {req.url}")
        
        # 3. Send Request
        resp = await self.context.http_client.send(req)
        
        # 4. Extract Variables
        if step.extract:
            self._extract_variables(step.extract, resp)
            
        # 5. Security Scan (if enabled)
        if step.scan and self.rule_executor:
            # Create a localized APIEndpoint for this step to run rules against
            endpoint = APIEndpoint(
                path=path,
                method=HttpMethod(step.method.upper()),
                summary=f"Workflow Step {step.id}",
                # Infer parameters from request for scanning
                parameters=self._infer_params(req)
            )
            print(f"       Scanning step {step.id}...")
            
            # Create a temporary context with merged headers for this step
            # This ensures rules use the tokens/cookies established in the workflow
            step_context = copy.copy(self.context)
            # Create a localized auth_headers dict
            step_context.auth_headers = copy.deepcopy(self.context.auth_headers)
            step_context.auth_headers.update(final_headers)
            
            await self.rule_executor.execute_on_endpoint(endpoint, step_context)

    def _substitute(self, value: Any) -> Any:
        """
        Replaces ${var} with values from context.variables.
        """
        if isinstance(value, str):
            # Simple ${var} substitution
            # Using loop to support multiple vars in one string
            for var_name, var_val in self.context.variables.items():
                placeholder = f"${{{var_name}}}"
                if placeholder in value:
                    value = value.replace(placeholder, str(var_val))
            return value
        elif isinstance(value, dict):
            return {k: self._substitute(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._substitute(v) for v in value]
        return value

    def _extract_variables(self, extractions: List[Extraction], resp):
        for extr in extractions:
            val = None
            if extr.source == "body":
                # Try JSON
                try:
                    data = json.loads(resp.body)
                    if extr.key:
                        val = self._get_json_value(data, extr.key)
                except:
                    pass
                
                # If Regex provided, use it on raw body string
                if extr.regex:
                    match = re.search(extr.regex, resp.body)
                    if match:
                        val = match.group(1) if match.groups() else match.group(0)
                        
            elif extr.source == "header":
                if extr.key:
                    val = resp.headers.get(extr.key)
            
            if val:
                self.context.variables[extr.variable] = val
                print(f"       [+] Extracted {extr.variable} = {val[:20]}...")

    def _get_json_value(self, data: Any, key: str) -> Any:
        """
        Dot notation access: "user.id"
        """
        keys = key.split('.')
        curr = data
        for k in keys:
            if isinstance(curr, dict):
                curr = curr.get(k)
            else:
                return None
        return curr
        
    def _infer_params(self, req: ScanRequest) -> List[Dict]:
        """
        Converts request params/body back to APIEndpoint parameter definition
        so that rules know what to fuzz.
        """
        params = []
        # Query Params
        for k in req.params:
            params.append({"name": k, "in": "query", "schema": {"type": "string"}})
            
        # Body Params (if dict)
        if isinstance(req.json_body, dict):
             for k in req.json_body:
                 params.append({"name": k, "in": "body", "schema": {"type": "string"}})
                 
        return params
