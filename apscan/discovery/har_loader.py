import json
from typing import List, Dict, Any
from urllib.parse import urlparse
from apscan.core.context import APIEndpoint, HttpMethod

class HARLoader:
    """Parses a HAR file into a list of APIEndpoints."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path

    def load(self) -> List[APIEndpoint]:
        endpoints = []
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Error loading HAR file: {e}")
            return []

        if 'log' not in data or 'entries' not in data['log']:
            print("[!] Invalid HAR file format.")
            return []

        for entry in data['log']['entries']:
            req = entry.get('request', {})
            url = req.get('url', '')
            method_str = req.get('method', 'GET').upper()
            
            if not url or method_str not in HttpMethod.__members__:
                continue
                
            method = HttpMethod[method_str]
            
            # Parse Path
            parsed = urlparse(url)
            path = parsed.path
            
            # Metadata
            summary = f"Imported from HAR: {url}"
            
            parameters = []
            
            # 1. Query Parameters
            if 'queryString' in req:
                for q in req['queryString']:
                    parameters.append({
                        "name": q['name'],
                        "in": "query",
                        "schema": {"type": "string", "default": q['value']},
                        "description": "From HAR QueryString"
                    })
            
            # 2. Body Parameters (postData)
            request_body_schema = None
            if 'postData' in req:
                post_data = req['postData']
                mime_type = post_data.get('mimeType', '')
                
                # Form Data
                if 'params' in post_data and post_data['params']:
                    for p in post_data['params']:
                        parameters.append({
                             "name": p['name'],
                             "in": "formData",
                             "schema": {"type": "string", "default": p.get('value', '')},
                             "description": "From HAR FormData"
                        })
                
                # JSON Body
                elif 'application/json' in mime_type and 'text' in post_data:
                    try:
                        json_body = json.loads(post_data['text'])
                        if isinstance(json_body, dict):
                            for k, v in json_body.items():
                                parameters.append({
                                    "name": k,
                                    "in": "body",
                                    "schema": {"type": "string", "default": v},
                                    "description": "From HAR JSON Body"
                                })
                            # Create mock schema for MassAssignment
                            request_body_schema = {
                                "type": "object",
                                "properties": {k: {"type": "string"} for k in json_body.keys()}
                            }
                    except json.JSONDecodeError:
                        pass
            
            endpoints.append(APIEndpoint(
                path=path,
                method=method,
                summary=summary,
                parameters=parameters,
                request_body_schema=request_body_schema
            ))
            
        return endpoints
