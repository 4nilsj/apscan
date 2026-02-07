from typing import List, Optional, Dict, Any
import logging
import json
import base64

from apscan.core.rule import ScannerRule
from apscan.core.context import ScanContext, APIEndpoint, Vulnerability

logger = logging.getLogger(__name__)

def extract_jwts_from_headers(headers: Dict[str, str]) -> List[str]:
    jwts = []
    auth = headers.get("Authorization", "")
    if "Bearer " in auth:
        token = auth.split("Bearer ")[1].strip()
        if token.count('.') == 2:
            jwts.append(token)
    return jwts

def decode_jwt_part(part: str) -> Optional[Dict[str, Any]]:
    part += '=' * (-len(part) % 4)
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception:
        return None

class JWTNoneAlgRule(ScannerRule):
    @property
    def id(self) -> str:
        return "JWT-001"
    
    @property
    def name(self) -> str:
        return "JWT 'None' Algorithm Accepted"

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        
        # We need to test the endpoint with a forged token.
        # But we need a valid token first to know we are authorized, or we assume context.auth_headers has one.
        jwts = extract_jwts_from_headers(context.auth_headers)
        if not jwts:
             # Fallback: Check endpoint parameters for 'header' type Authorization
             for param in endpoint.parameters:
                 if param.get("in") == "header" and param.get("name").lower() == "authorization":
                     val = param.get("default", "") or param.get("example", "")
                     if "Bearer " in val:
                         token = val.split("Bearer ")[1].strip()
                         if token.count('.') == 2:
                             jwts.append(token)
                             
        if not jwts and context.target.curl_command and "Bearer " in context.target.curl_command:
             # Fallback 2: Raw cURL string
             import re
             match = re.search(r'Bearer\s+([A-Za-z0-9\-\._~+/]+=*)', context.target.curl_command)
             if match:
                 token = match.group(1)
                 if token.count('.') == 2:
                     jwts.append(token)

        if not jwts:
            return []
            
        original_token = jwts[0]
        parts = original_token.split('.')
        if len(parts) != 3:
            return []

        # Only check once per endpoint
        
        # Construct forgery
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
        payload = parts[1]
        forgery = f"{header}.{payload}."
        
        try:
            new_headers = context.auth_headers.copy()
            new_headers["Authorization"] = f"Bearer {forgery}"
            
            # Replay the initial request configuration (GET/POST) but with new header
            # Note: endpoint doesn't store the original body/params perfectly if it was a complex mutation.
            # But for JWT check, simple replay of the endpoint is usually enough.
            # If endpoint.method is POST, we might need a body.
            # For this rule, we assume we just probe the endpoint.
            
            # Minimal effort body? Or should we use RequestGenerator?
            from apscan.core.context import ScanRequest # ensure import
            json_body = endpoint.request_body_schema if endpoint.request_body_schema else {}
            
            req = ScanRequest(
                method=endpoint.method,
                url=endpoint.path,
                headers=new_headers,
                json_body=json_body
            )
            
            res = await context.http_client.send(req)
            
            if res.status_code == 200:
                findings.append(Vulnerability(
                    rule_id=self.id,
                    name=self.name,
                    description="The server accepts JWTs signed with the 'none' algorithm, allowing authentication bypass.",
                    severity="CRITICAL",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence="Server accepted a JWT with 'alg': 'none'.",
                    recommendation="Reject all JWTs with 'alg': 'none' in your verification logic.",
                    reproduce_curl=f"curl -X {endpoint.method} {endpoint.path} -H 'Authorization: Bearer {forgery}'"
                ))
        except Exception:
            pass
            
        return findings

class JWTSensitiveInfoRule(ScannerRule):
    @property
    def id(self) -> str:
        return "JWT-002"
    
    @property
    def name(self) -> str:
        return "Sensitive Information in JWT"

    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        findings = []
        jwts = extract_jwts_from_headers(context.auth_headers)
        if not jwts:
            return []
            
        token = jwts[0]
        parts = token.split('.')
        if len(parts) != 3:
            return []
            
        payload = decode_jwt_part(parts[1])
        if not payload:
            return []
            
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "balance", "email"]
        found_keys = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
        
        if found_keys:
            # Dedupe globally to avoid spamming every endpoint with same finding
            target_key = f"{self.id}:{context.target_url}"
            if target_key in context.scanned_hashes:
                return []
            context.scanned_hashes.add(target_key)
            
            findings.append(Vulnerability(
                rule_id=self.id,
                name=self.name,
                description="The JWT payload contains sensitive information which is easily decodable.",
                severity="LOW",
                endpoint="Global (Token Analysis)",
                method="N/A",
                evidence=f"JWT Payload contains sensitive keys: {', '.join(found_keys)}",
                recommendation="Do not store sensitive data in JWT payloads.",
                reproduce_curl="Inspect the token in a JWT debugger."
            ))
            
        return findings
