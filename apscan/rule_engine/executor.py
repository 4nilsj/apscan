import asyncio
from typing import List, Any
from apscan.core.context import ScanContext, APIEndpoint
from apscan.core.rule import ScannerRule

class RuleExecutor:
    """
    Manages the execution of rules against the discovered attack surface.
    """
    def __init__(self, context: ScanContext):
        self.context = context
        self.rules = []

    def set_rules(self, rules: List[Any]):
        self.rules = rules

    async def execute(self, rules: List[Any] = None):
        """
        Executes a list of rules against all endpoints in context endpoints.
        """
        current_rules = rules or self.rules
        if not current_rules:
            print("[!] No rules provided for execution.")
            return

        if not self.context.endpoints:
            print("[*] No endpoints to scan.")
            return

        print(f"[*] Beginning attack phase on {len(self.context.endpoints)} endpoints with {len(current_rules)} rules...")

        # Concurrency Control
        sem = asyncio.Semaphore(10) # 10 Concurrent requests/tasks
        print(f"[*] Concurrency set to 10 workers.")

        tasks = []
        for endpoint in self.context.endpoints:
             for rule in current_rules:
                 tasks.append(self._safe_run_rule(rule, endpoint, sem))
        
        await asyncio.gather(*tasks)

    async def execute_on_endpoint(self, endpoint: APIEndpoint, context: ScanContext = None):
        """
        Executes loaded rules against a single specific endpoint (e.g. from a Workflow).
        """
        # Prefer passed context if available, else use self.context
        active_context = context or self.context

        if not self.rules:
            print("[!] No rules loaded to execute on endpoint.")
            return

        print(f"[*] Scanning {endpoint.method.value} {endpoint.path} with {len(self.rules)} rules...")
        sem = asyncio.Semaphore(5)
        tasks = []
        for rule in self.rules:
             tasks.append(self._safe_run_rule(rule, endpoint, sem, active_context))
        
        await asyncio.gather(*tasks)

    async def _safe_run_rule(self, rule, endpoint, semaphore=None, context=None):
        active_context = context or self.context
        try:
            if semaphore:
                async with semaphore:
                    findings = await rule.run(endpoint, active_context)
            else:
                 findings = await rule.run(endpoint, active_context)

            if findings:
                print(f"    [!] {rule.name}: found {len(findings)} issues on {endpoint.path}")
                active_context.findings.extend(findings)
            return findings
        except Exception as e:
            # print(f"    [!] Error running rule {rule.name} on {endpoint.path}: {e}")
            return []
