import shlex
import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from apscan.core.context import APIEndpoint, HttpMethod

class CurlLoader:
    """Parses a CURL command into a single APIEndpoint."""
    
    def __init__(self, command: str):
        self.command = command

    def load(self) -> List[APIEndpoint]:
        try:
            # Simple shlex split to handle quotes
            args = shlex.split(self.command)
        except Exception:
            # Fallback if shlex fails (e.g. invalid shell syntax)
            # returning empty list
            return []

        url = ""
        method = HttpMethod.GET
        headers = {}
        body = None
        
        # Iterate args
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in ["-X", "--request"]:
                # Next arg is method
                if i + 1 < len(args):
                    m_str = args[i+1].upper()
                    if m_str in HttpMethod.__members__:
                        method = HttpMethod[m_str]
                    i += 1
            elif arg in ["-H", "--header"]:
                if i + 1 < len(args):
                    header_str = args[i+1]
                    if ":" in header_str:
                        key, val = header_str.split(":", 1)
                        headers[key.strip()] = val.strip()
                    i += 1
            elif arg in ["-d", "--data", "--data-raw", "--data-binary"]:
                if i + 1 < len(args):
                    body = args[i+1]
                    # If method was GET, imply POST if data is present (curl behavior)
                    if method == HttpMethod.GET:
                        method = HttpMethod.POST
                    i += 1
            elif arg.startswith("http://") or arg.startswith("https://"):
                url = arg
            
            i += 1
            
        # Fallback URL detection if positional
        if not url:
            for arg in args:
                if arg.startswith("http"):
                    url = arg
                    break
        
        if not url:
            print("[!] Could not parse URL from curl command.")
            return []

        # Parse Endpoint Path from URL
        parsed = urlparse(url)
        path = parsed.path
        if parsed.query:
            # We treat query params as... well in the path for APIEndpoint for now
            # OR we parse them?
            # APIEndpoint 'path' is usually the route template.
            # If user provides '/users/123', that's the path.
            # We might want to genericize it later, but keeping it raw is fine for single scan.
            pass

        # Construct Endpoint
        # We need to note that this endpoint has specific headers/body.
        # However, APIEndpoint model is mainly Metadata (parameters schema).
        # We should infer parameters from the CURL request if possible?
        # MVP: Just return the endpoint with empty parameters and let rules Fuzz it?
        # WAIT. BOLA/Injection rules look at `endpoint.parameters`.
        # If I return empty parameters, the rules will skip!
        # I MUST parse parameters from Query String and Body (JSON).
        
        parameters = []
        
        # 1. Query Params
        if parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            for k, v in qs.items():
                parameters.append({
                    "name": k,
                    "in": "query",
                    "schema": {"type": "string"},
                    "description": "Extracted from curl"
                })
        
        # 2. Body Params
        if body:
            import json
            from urllib.parse import parse_qs
            
            # Try JSON
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    for k, v in json_data.items():
                        parameters.append({
                            "name": k,
                            "in": "body", # Using generic 'body' location
                            "schema": {"type": "string", "default": v},
                            "description": "Extracted from curl JSON body"
                        })
            except json.JSONDecodeError:
                # Try Form Data
                qs = parse_qs(body)
                for k, v in qs.items():
                    # qs values are lists
                    val = v[0] if v else ""
                    parameters.append({
                        "name": k,
                        "in": "formData",
                        "schema": {"type": "string", "default": val},
                        "description": "Extracted from curl Form Data"
                    })

        return [APIEndpoint(
            path=path,
            method=method,
            summary="Imported from cURL",
            parameters=parameters,
            # We explicitly set request_body_schema to mimic OpenAPI if we found JSON
            request_body_schema={"type": "object", "properties": {p['name']: p['schema'] for p in parameters if p['in'] == 'body'}} if any(p['in'] == 'body' for p in parameters) else None
        )]
