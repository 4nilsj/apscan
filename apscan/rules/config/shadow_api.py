from typing import List
from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, Severity, HttpMethod, ScanRequest
import asyncio

class ShadowAPIRule(ScannerRule):
    @property
    def id(self) -> str:
        return "SHADOW_API"

    @property
    def name(self) -> str:
        return "Shadow API Detection"

    def __init__(self):
        self.severity = Severity.LOW # Can be High if sensitive, but detection itself is Info/Low
        self.description = "Detects undocumented or shadow API versions (e.g. /v1, /dev, /beta)."
        self.guesses = ["v1", "v2", "v3", "api/v1", "api/v2", "dev", "test", "beta", "old", "admin", "internal"]
        self.checked_bases = set()

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        print(f"[DEBUG] ShadowAPIRule INVOKED for {endpoint.path}")
        # This rule effectively runs once per unique base path, not per endpoint.
        # But we hook into run() which is per endpoint. We use a set to avoid re-checking.
        
        original_path = endpoint.path
        # Heuristic: try to replace the first segment or prefix
        # e.g., /api/users -> try /api/v1/users, /dev/users
        # Simplified: Just try to access the guesses relative to root
        
        # Actually proper Shadow API logic:
        # If we see /v1/users, check /v2/users
        # If we see /api/users, check /api/dev/users
        
        findings = []
        
        # Naive approach: check if root + guess exists
        # Better approach: Look at current path structure
        
        # Only run if we haven't checked this specific pattern
        # But context.scanned_hashes handles dedup of *requests* not logical checks.
        # We need self.checked_bases
        
        # Let's try common prefixes on the root URL
        if "root_checked" not in self.checked_bases:
            print(f"[DEBUG] ShadowAPIRule: Checking root variants for {context.target_url}")
            self.checked_bases.add("root_checked")
            for guess in self.guesses:
                url = f"{context.target_url.rstrip('/')}/{guess}"
                exists = await self._check_exists(context, url)
                print(f"[DEBUG] ShadowAPIRule: Checking {url} -> {exists}")
                if exists:
                    findings.append(Vulnerability(
                        rule_id=self.id,
                        name=self.name,
                        severity=Severity.INFO,
                        description=f"Found potential shadow or undocumented API location: {url}",
                        endpoint=f"/{guess}",
                        method=HttpMethod.GET,
                        evidence=f"Received 200 OK for {url}",
                        recommendation="Ensure all API endpoints are documented and deprecated versions are disabled."
                    ))

        # Also try to swap version numbers
        # e.g. /v1/foo -> /v2/foo
        parts = original_path.strip('/').split('/')
        for i, part in enumerate(parts):
            if part.lower().startswith('v') and part[1:].isdigit():
                # It's a version! Try others
                ver = int(part[1:])
                next_ver = f"v{ver+1}"
                new_parts = list(parts)
                new_parts[i] = next_ver
                new_path = "/" + "/".join(new_parts)
                
                full_url = context.target_url.rstrip('/') + new_path
                # Check uniqueness to avoid spamming
                if full_url not in self.checked_bases:
                    self.checked_bases.add(full_url)
                    if await self._check_exists(context, full_url):
                         findings.append(Vulnerability(
                            rule_id=self.id,
                            name="Shadow API Version",
                            severity=Severity.MEDIUM,
                            description=f"Found undocumented API version: {new_path}",
                            endpoint=new_path,
                            method=HttpMethod.GET,
                            evidence=f"Received 200 OK for {new_path}",
                            recommendation="Disable undocumented API versions."
                        ))

        return findings

    async def _check_exists(self, context, url):
        req = ScanRequest(method=HttpMethod.GET, url=url)
        res = await context.http_client.send(req)
        # 200 OK or 401 Unauthorized usually means it exists
        return res.status_code in [200, 401, 403]
