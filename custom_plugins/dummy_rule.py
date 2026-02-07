from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod

class CustomHelloRule(ScannerRule):
    @property
    def id(self) -> str:
        return "CUSTOM_RULE_01"

    @property
    def name(self) -> str:
        return "Custom Hello Rule"

    def __init__(self):
        self.severity = Severity.INFO
        self.description = "A custom rule loaded from plugins."

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        # Always trigger on the root path just to prove it loaded
        if endpoint.path == "/" or endpoint.path == "":
            return [Vulnerability(
                rule_id=self.id,
                name=self.name,
                severity=self.severity,
                description="Custom rule execution confirmed.",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence="Plugin system active."
            )]
        return []
