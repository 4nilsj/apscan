from typing import List, Dict, Any
import re
from apscan.core.context import APIEndpoint, Vulnerability, Severity, ScanContext, ScanRequest, HttpMethod
from apscan.core.rule import ScannerRule
from apscan.rule_engine.matcher import DetectionMatcher

class YAMLRule(ScannerRule):
    def __init__(self, config: Dict[str, Any]):
        self._config = config
        self._id = config.get("id", "UNKNOWN")
        self._name = config.get("name", "Unknown Rule")
        self.definition = config.get("request", {})
        self.matcher = DetectionMatcher(config.get("match", {}))

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # Filter: Only run if method matches (if specified)
        req_def = self.definition
        if "method" in req_def and req_def["method"].upper() != endpoint.method.value:
            return []

        # Target Logic
        target_path = req_def.get("path")
        
        if target_path:
            full_url = context.target_url.rstrip('/') + target_path
            method = HttpMethod(req_def.get("method", "GET").upper())
        else:
            full_url = context.target_url.rstrip('/') + endpoint.path
            method = endpoint.method

        # Request Construction
        headers = self._config.get("headers", {}).copy() # Use copy to avoid mutating config
        
        # Merge global auth headers unless explicit opt-out (future)
        # For now, always merge
        headers.update(context.auth_headers)
        
        req = ScanRequest(
            method=method,
            url=full_url,
            headers=headers
        )

        response = await context.http_client.send(req)

        # Matching Logic Delegated
        if self.matcher.matches(response):
             return [Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=Severity(self._config.get("severity", "MEDIUM")),
                description=self._config.get("description", "Vulnerability detected via YAML rule."),
                impact=self._config.get("impact", "Potential security risk."),
                endpoint=target_path if target_path else endpoint.path,
                method=method,
                evidence=f"Matched criteria. Status: {response.status_code}\nBody: {response.body[:200]}...",
                recommendation=self._config.get("remediation", "Check configuration.") # Support legacy key 'remediation' in yaml for now, or recommendation
            )]
        
        return []
