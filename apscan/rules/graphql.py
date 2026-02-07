from typing import List, Optional
import logging
import httpx
import json

from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability, ScanRequest

logger = logging.getLogger(__name__)

class GraphQLIntrospectionRule(ScannerRule):
    @property
    def id(self) -> str:
        return "GQL-001"
        
    @property
    def name(self) -> str:
        return "GraphQL Introspection Enabled"

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        desc = endpoint.description or ""
        if not desc.lower().startswith("graphql"):
             # Or check metadata if available
             return []

        # Target Key for deduplication (per URL)
        target_key = f"{self.id}:{context.target_url}"
        if target_key in context.scanned_hashes:
            return []
        context.scanned_hashes.add(target_key)
        
        findings = []
        introspection_payload = {"query": "{ __schema { queryType { name } } }"}
        
        try:
            # We assume endpoint.path is the full URL or we construct it
            # From GraphQLLoader, endpoint.path is the full target URL
            url = endpoint.path
            
            headers = {"Content-Type": "application/json"}
            headers.update(context.auth_headers)
            
            req = ScanRequest(
                 method="POST",
                 url=url,
                 headers=headers,
                 json_body=introspection_payload
            )
            res = await context.http_client.send(req)
            
            if res.status_code == 200 and "__schema" in res.body:
                findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    description="GraphQL introspection is allowed, which exposes the full schema structure to attackers.",
                    severity="LOW",
                    endpoint=url,
                    method="POST",
                    evidence="Server responded with schema definition to introspection query.",
                    recommendation="Disable GraphQL introspection in production environments.",
                    reproduce_curl=f"curl -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(introspection_payload)}'"
                ))
        except Exception as e:
            logger.debug(f"GraphQL Introspection check failed: {e}")
            
        return findings

class GraphQLDepthLimitRule(ScannerRule):
    @property
    def id(self) -> str:
        return "GQL-002"
    
    @property
    def name(self) -> str:
        return "GraphQL No Query Depth Limit"

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        desc = endpoint.description or ""
        if not desc.lower().startswith("graphql"):
            return []

        target_key = f"{self.id}:{context.target_url}"
        if target_key in context.scanned_hashes:
            return []
        context.scanned_hashes.add(target_key)
        
        findings = []
        # Construct a deep query
        deep_query = "{ __typename " + " ".join(["{ __typename" for _ in range(20)]) + " ".join(["}" for _ in range(20)]) + " }"
        payload = {"query": deep_query}
        
        try:
            url = endpoint.path
            headers = {"Content-Type": "application/json"}
            headers.update(context.auth_headers)
            
            req = ScanRequest(
                 method="POST",
                 url=url,
                 headers=headers,
                 json_body=payload
            )
            res = await context.http_client.send(req)
            
            if res.status_code == 200 and "data" in (json.loads(res.body) if res.body else {}):
                 findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    description="The API allows deeply nested queries, which can cause Denial of Service (DoS).",
                    severity="MEDIUM",
                    endpoint=url,
                    method="POST",
                    evidence="Server processed a query with 20 levels of nesting without error.",
                    recommendation="Implement a Query Depth Limit (e.g., max 10 levels) in your GraphQL server configuration.",
                    reproduce_curl=f"curl -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(payload)}'"
                 ))
        except Exception as e:
             logger.debug(f"GraphQL Depth check failed: {e}")
             
        return findings

class GraphQLBatchingRule(ScannerRule):
    @property
    def id(self) -> str:
        return "GQL-003"
    
    @property
    def name(self) -> str:
        return "GraphQL Batching Enabled"

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        desc = endpoint.description or ""
        if not desc.lower().startswith("graphql"):
            return []

        target_key = f"{self.id}:{context.target_url}"
        if target_key in context.scanned_hashes:
            return []
        context.scanned_hashes.add(target_key)
        
        findings = []
        payload = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ]
        
        try:
            url = endpoint.path
            headers = {"Content-Type": "application/json"}
            headers.update(context.auth_headers)
            
            req = ScanRequest(
                 method="POST",
                 url=url,
                 headers=headers,
                 json_body=payload
            )
            res = await context.http_client.send(req)
            
            try:
                data = json.loads(res.body)
            except:
                data = None
                
            if res.status_code == 200 and isinstance(data, list) and len(data) == 3:
                 findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    description="Array-based batching is enabled, enabling brute-force attacks and DoS amplification.",
                    severity="LOW",
                    endpoint=url,
                    method="POST",
                    evidence="Server processed an array of 3 queries and returned an array of 3 responses.",
                    recommendation="Disable query batching if not required, or implement strict rate limiting on batched operations.",
                    reproduce_curl=f"curl -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(payload)}'"
                ))
        except Exception:
            pass
            
        return findings
