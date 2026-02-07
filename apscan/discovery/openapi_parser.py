import json
import yaml
import httpx
from typing import List, Dict, Any, Union
from apscan.core.context import APIEndpoint, HttpMethod

class OpenAPILoader:
    def __init__(self, target: str):
        self.target = target

    def load(self) -> List[APIEndpoint]:
        print(f"[*] Parsing OpenAPI spec from {self.target}")
        spec = self._load_spec(self.target)
        if not spec:
            return []
            
        return self._parse_endpoints(spec)

    def _load_spec(self, target: str) -> Dict[str, Any]:
        try:
            content = ""
            if target.startswith("http://") or target.startswith("https://"):
                try:
                    # Sync call for simplicity in this loader, or use asyncio run
                    # Ideally orchestrator calls this in a thread or we use async.
                    # Since load() is sync in current design, we'll use httpx.get
                    response = httpx.get(target, timeout=10)
                    response.raise_for_status()
                    content = response.text
                except Exception as e:
                    print(f"[!] HTTP Error fetching spec: {e}")
                    return {}
            else:
                # Local file
                try:
                    with open(target, 'r') as f:
                        content = f.read()
                except Exception as e:
                    print(f"[!] File Error: {e}")
                    return {}

            # Parse
            try:
                return yaml.safe_load(content) # yaml.safe_load handles JSON too
            except Exception as e:
                print(f"[!] Parse Error: {e}")
                return {}
        except Exception as e:
            print(f"[!] Error loading spec: {e}")
            return {}

    def _parse_endpoints(self, spec: Dict[str, Any]) -> List[APIEndpoint]:
        # User Provided Logic:
        # for path, methods in spec["paths"].items():
        #    for method in methods:
        #        endpoints.append(...)
        
        endpoints = []
        paths = spec.get("paths", {})
        
        for path, methods in paths.items():
            for method_str, details in methods.items():
                # Filter valid HTTP methods
                if method_str.upper() not in HttpMethod.__members__:
                    continue

                method = HttpMethod[method_str.upper()]
                
                # Basic Metadata extraction to satisfy APIEndpoint model
                # User's MVP dict: {"path": path, "method": method.upper()}
                # We map to APIEndpoint
                
                # Extract parameters
                params = details.get("parameters", [])
                
                # Extract Request Body (OpenAPI 3.0+)
                request_body = details.get("requestBody", {})
                content = request_body.get("content", {})
                
                # Parse JSON body params
                if "application/json" in content:
                    schema = content["application/json"].get("schema", {})
                    
                    # Resolve Ref if present
                    if "$ref" in schema:
                         ref_path = schema["$ref"]
                         # Simple Ref Resolution for #/components/schemas/Name
                         if ref_path.startswith("#/components/schemas/"):
                             schema_name = ref_path.split("/")[-1]
                             schema = spec.get("components", {}).get("schemas", {}).get(schema_name, {})

                    # Handle direct properties
                    properties = schema.get("properties", {})
                    for prop_name, prop_details in properties.items():
                        params.append({
                            "name": prop_name,
                            "in": "body",
                            "schema": prop_details,
                            "required": prop_name in schema.get("required", [])
                        })
                    
                endpoints.append(APIEndpoint(
                    path=path,
                    method=method,
                    summary=details.get("summary"),
                    parameters=params
                ))
        
        return endpoints
