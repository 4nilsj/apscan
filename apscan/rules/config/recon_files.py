from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod, ScanRequest

class ReconFilesRule(ScannerRule):
    @property
    def id(self) -> str:
        return "RECON_FILES"

    @property
    def name(self) -> str:
        return "Reconnaissance Files"

    def __init__(self):
        self.severity = Severity.INFO
        self.description = "Detects standard security and configuration files."
        self.files = ["/security.txt", "/.well-known/security.txt", "/robots.txt", "/ads.txt"]
        self.checked = False

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # Run once per scan target
        if self.checked:
            return []
        self.checked = True
        
        base = context.target_url.rstrip('/')
        
        for path in self.files:
            url = base + path
            req = ScanRequest(method=HttpMethod.GET, url=url)
            res = await context.http_client.send(req)
            
            if res.status_code == 200:
                findings.append(Vulnerability(
                    rule_id=self.id,
                    name="Recon: File Found",
                    severity=Severity.INFO,
                    description=f"Found discovered file: {path}",
                    endpoint=path,
                    method=HttpMethod.GET,
                    evidence=f"File exists at {url} (200 OK)",
                    recommendation="Review contents to ensure no sensitive info is leaked (e.g. disallowed paths in robots.txt)."
                ))
                
        return findings
