import asyncio
from typing import List
from apscan.core.context import ScanTarget, Vulnerability, APIEndpoint, ScanContext
from apscan.utils.http import HTTPClient

# Core Components
from apscan.discovery.openapi_parser import OpenAPILoader
from apscan.reporting.json_report import JSONReporter
from apscan.reporting.html_report import HTMLReporter
from apscan.rule_engine.loader import RuleLoader
from apscan.rule_engine.executor import RuleExecutor

class ScanOrchestrator:
    def __init__(self, target: ScanTarget):
        self.http_client = HTTPClient()
        self.context = ScanContext(target, self.http_client)
        self.reporters = [JSONReporter(), HTMLReporter()] # Added HTML
        
        self.rule_loader = RuleLoader()
        self.rule_executor = RuleExecutor(self.context)
        self.scanner_rules = []

    async def run(self):
        """
        Traffic Cop: Manages the lifecycle of the scan.
        """
        try:
            await self.discover_apis()
            self.load_rules()
            await self.authenticate()
            await self.execute_rules()
            self.generate_report()
            return self.context.findings
        finally:
            await self.http_client.close()

    async def discover_apis(self):
        """Step 1: Discover API endpoints."""
        if self.context.target.postman_file:
            print(f"[*] Parsing Postman Collection: {self.context.target.postman_file}...")
            from apscan.discovery.postman_loader import PostmanLoader
            loader = PostmanLoader(self.context.target.postman_file)
            self.context.endpoints = loader.load()
            self._infer_base_url_from_endpoints()
            
        elif self.context.target.list_file:
            print(f"[*] Parsing Endpoint List: {self.context.target.list_file}...")
            from apscan.discovery.list_loader import ListLoader
            loader = ListLoader(self.context.target.list_file)
            self.context.endpoints = loader.load()
            self._infer_base_url_from_endpoints()
            
        elif self.context.target.har_file:
            print(f"[*] Parsing HAR file: {self.context.target.har_file}...")
            from apscan.discovery.har_loader import HARLoader
            loader = HARLoader(self.context.target.har_file)
            self.context.endpoints = loader.load()
            self._infer_base_url_from_endpoints()
                 
        elif self.context.target.curl_command:
            print(f"[*] Parsing cURL command...")
            print(f"[*] Parsing cURL command...")
            from apscan.discovery.curl_loader import CurlLoader
            loader = CurlLoader(self.context.target.curl_command)
            self.context.endpoints = loader.load()
            
            # Infer target_url from the parsed first endpoint if URL missing
            # But wait, we need the HOST base.
            # Loader extracted path. The `url` passed to ScanTarget might be None.
            # We need to re-extract the base URL from the curl command because `ScanContext.target_url` is used by rules to build full URLs.
            # Hack: CurlLoader logic didn't return the full base URL.
            # I should update CurlLoader or extract it here.
            # Let's extract it from the command string using regex or simple logic here to save time.
            import re
            match = re.search(r'https?://[^\s"\']+', self.context.target.curl_command)
            if match:
                 full_url = match.group(0)
                 # We want the BASE. e.g. http://api.com
                 # `ScanContext.target_url` is usually the base (e.g. http://... from OpenAPI).
                 # If we set it to the full URL, rules doing `target_url + endpoint.path` will double append.
                 # E.g. target="http://api.com/users/1", endpoint.path="/users/1"
                 # Result: http://api.com/users/1/users/1 -> WRONG.
                 
                 # Logic fix: If CurlLoader sets `path`, it sets it relative or absolute?
                 # My CurlLoader implementation set `path = parsed.path` (e.g. `/users/1`).
                 # So `target_url` should be `scheme://netloc`.
                 from urllib.parse import urlparse
                 parsed = urlparse(full_url)
                 self.context.target_url = f"{parsed.scheme}://{parsed.netloc}"
                 print(f"[*] Inferred Base URL: {self.context.target_url}")
            else:
                 print("[!] Could not determine Target URL from curl.")

        elif self.context.target.graphql:
            print(f"[*] Starting GraphQL Discovery on {self.context.target.url}...")
            from apscan.discovery.graphql_loader import GraphQLLoader
            loader = GraphQLLoader(self.context.target.url)
            self.context.endpoints = await loader.load() # GraphQL loader is async
            self.context.target_url = self.context.target.url
            
        else:
            print(f"[*] Starting API Discovery on {self.context.target.url}...")
            loader = OpenAPILoader(self.context.target.url)
            self.context.endpoints = loader.load()
            
            # Determine base URL for scanning
            if self.context.endpoints and self.context.target.url:
                 # Simplified heuristic
                 base_url = self.context.target.url.rsplit('/', 1)[0]
                 self.context.target_url = base_url

        print(f"[*] Discovered {len(self.context.endpoints)} endpoints.")

    def load_rules(self):
        """Step 2: Load security rules."""
        self.scanner_rules = self.rule_loader.load_rules()
        
        # Load Plugins
        if self.context.target.plugin_dir:
            self.rule_loader.load_plugins(self.context.target.plugin_dir)
            # Re-fetch rules as list is updated in loader
            self.scanner_rules = self.rule_loader.rules
            
        self.rule_executor.set_rules(self.scanner_rules) # Pass to executor
        print(f"[*] Loaded {len(self.scanner_rules)} rules.")

    def _infer_base_url_from_endpoints(self):
        """Helper to infer target_url from discovered endpoints."""
        if self.context.endpoints:
            # Try to grab full URL from summary if available
            # Our Loaders put "Imported from ...: URL" in summary
            first = self.context.endpoints[0]
            if "Imported from" in str(first.summary) and "http" in str(first.summary):
                # Heuristic extraction
                import re
                match = re.search(r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+', str(first.summary))
                if match:
                    full_url = match.group(0)
                    from urllib.parse import urlparse
                    parsed = urlparse(full_url)
                    self.context.target_url = f"{parsed.scheme}://{parsed.netloc}"
                    print(f"[*] Inferred Base URL: {self.context.target_url}")
                    return

            # Fallback if we assume standard OpenAPI flow or failed parsing
            if self.context.target.url:
                 # Standard flow
                 pass
            else:
                 print("[!] Warning: Cloud not infer base URL from endpoints. Scanning might fail if paths are relative.")

    async def authenticate(self):
        """Step 3: Handle authentication."""
        # For MVP, we check if target has auth_config (from CLI/Config)
        # Assuming target.auth_config = {"type": "apikey", "key": "...", "header": "..."}
        
        auth_config = self.context.target.auth_config
        if auth_config:
            from apscan.auth.providers import ApiKeyAuth, BasicAuth, BearerAuth, CookieAuth, OAuth2ClientCredentials
            
            provider = None
            auth_type = auth_config.get("type")
            
            if auth_type == "apikey":
                provider = ApiKeyAuth(
                    key=auth_config.get("key"), 
                    header=auth_config.get("header", "X-API-Key")
                )
            elif auth_type == "basic":
                provider = BasicAuth(
                    username=auth_config.get("username"),
                    password=auth_config.get("password")
                )
            elif auth_type == "bearer":
                provider = BearerAuth(token=auth_config.get("token"))
            elif auth_type == "cookie":
                provider = CookieAuth(cookie_string=auth_config.get("cookie"))
            elif auth_type == "oauth2":
                provider = OAuth2ClientCredentials(
                    token_url=auth_config.get("token_url"),
                    client_id=auth_config.get("client_id"),
                    client_secret=auth_config.get("client_secret"),
                    scope=auth_config.get("scope")
                )
            
            if provider:
                headers = provider.get_headers()
                self.context.auth_headers.update(headers)
                print(f"[*] Authentication configured ({auth_type}). Headers: {list(headers.keys())}")

    async def execute_rules(self):
        """Step 4: Execute rules against the attack surface."""
        await self.rule_executor.execute(self.scanner_rules)
        await self.enrich_findings()

    async def enrich_findings(self):
        """Step 4.5: Enrich findings with AI Analysis if configured."""
        ai_config = self.context.target.ai_config
        if not ai_config or not ai_config.get("provider"):
            return

        print(f"[*] Enriching {len(self.context.findings)} findings with AI ({ai_config['provider']})...")
        
        from apscan.ai.providers import GeminiProvider, OpenAIProvider, LocalProvider
        
        provider = None
        key = ai_config.get("key")
        model = ai_config.get("model")
        p_type = ai_config.get("provider").lower()
        
        if p_type == "gemini":
            provider = GeminiProvider(api_key=key, model_name=model or "gemini-1.5-flash")
        elif p_type == "openai":
            provider = OpenAIProvider(api_key=key, model_name=model or "gpt-4o-mini")
        elif p_type == "local":
            provider = LocalProvider(base_url=ai_config.get("base_url", "http://localhost:1234/v1"))
        elif p_type == "mock":
            from apscan.ai.providers import MockAIProvider
            provider = MockAIProvider()
            
        if not provider:
            print(f"[!] Unknown AI Provider: {p_type}")
            return
            
        # Enrich sequentially or semi-parallel? Sequential for safety with rate limits.
        for finding in self.context.findings:
            if finding.severity in ["HIGH", "CRITICAL"]: # Save tokens, only analyze important ones
                analysis = provider.analyze_finding(finding)
                finding.ai_analysis = analysis
                # formatting check
                if "False Positive" in analysis and "High Confidence" in analysis:
                     finding.ai_confidence = "AI suggests False Positive"

    async def run_workflows(self, workflow_files: List[str]):
        """
        Executes a list of workflow files.
        """
        from apscan.workflows.executor import WorkflowExecutor
        from apscan.workflows.loader import WorkflowLoader 
        
        executor = WorkflowExecutor(self.context, self.rule_executor)
        loader = WorkflowLoader()
        
        for file_path in workflow_files:
            try:
                workflow = loader.load(file_path)
                await executor.execute(workflow)
                # After workflow, we might want to generate report immediately?
                # Or wait for full run.
            except Exception as e:
                print(f"[!] Error executing workflow {file_path}: {e}")
            
    def generate_report(self):
        """Step 5: Generate reports."""
        print("[*] Generating reports...")
        for reporter in self.reporters:
            reporter.generate(self.context)
