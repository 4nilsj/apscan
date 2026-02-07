import json
from typing import List, Dict, Any, Union
from apscan.core.context import APIEndpoint, HttpMethod

class PostmanLoader:
    """Parses a Postman Collection (v2.1) into APIEndpoints."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path

    def load(self) -> List[APIEndpoint]:
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Error loading Postman file: {e}")
            return []

        if 'item' not in data:
            print("[!] Invalid Postman Collection format.")
            return []

        endpoints = []
        self._traverse_items(data['item'], endpoints)
        return endpoints

    def _traverse_items(self, items: List[Dict], endpoints: List[APIEndpoint]):
        for item in items:
            if 'item' in item:
                # Folder
                self._traverse_items(item['item'], endpoints)
            elif 'request' in item:
                # Request
                endpoint = self._parse_request(item)
                if endpoint:
                    endpoints.append(endpoint)

    def _parse_request(self, item: Dict) -> Union[APIEndpoint, None]:
        req = item['request']
        name = item.get('name', 'Postman Request')
        
        # Method
        method_str = req.get('method', 'GET').upper()
        if method_str not in HttpMethod.__members__:
            return None
        method = HttpMethod[method_str]
        
        # URL
        url_obj = req.get('url')
        if isinstance(url_obj, str):
            raw_url = url_obj
        else:
            raw_url = url_obj.get('raw', '')
            
        if not raw_url:
            return None

        # Parse Path (simplified logic to strip protocol/host)
        # We need a robust way if variable syntax {{BaseUrl}} is used.
        # For now, we assume FULL URLs or we keep raw.
        # Ideally we parse the `path` array from url object if available.
        path = ""
        if isinstance(url_obj, dict) and 'path' in url_obj:
            p_parts = url_obj['path']
            if isinstance(p_parts, list):
                path = "/" + "/".join(p_parts)
            else:
                path = str(p_parts)
        else:
            # Fallback for string URL
            from urllib.parse import urlparse
            # Handle variables like {{url}}/path
            if "{{" in raw_url:
                # Heuristic: Find first slash after schema
                parts = raw_url.split('/', 3)
                if len(parts) > 3:
                     path = "/" + parts[3]
                else:
                     path = raw_url # Fallback
            else:
                parsed = urlparse(raw_url)
                path = parsed.path

        parameters = []
        
        # Query Params
        if isinstance(url_obj, dict) and 'query' in url_obj:
            for q in url_obj['query']:
                if not q.get('disabled'):
                    parameters.append({
                        "name": q['key'],
                        "in": "query",
                        "schema": {"type": "string", "default": q.get('value', '')},
                        "description": "Postman Query Param"
                    })
        
        # Body
        body = req.get('body', {})
        request_body_schema = None
        if body and body.get('mode') == 'raw':
            raw = body.get('raw', '')
            # Try JSON
            try:
                json_body = json.loads(raw)
                if isinstance(json_body, dict):
                     for k, v in json_body.items():
                        parameters.append({
                            "name": k,
                            "in": "body",
                            "schema": {"type": "string", "default": v},
                            "description": "Postman JSON Body"
                        })
                     request_body_schema = {
                        "type": "object",
                         "properties": {k: {"type": "string"} for k in json_body.keys()}
                     }
            except:
                pass
        elif body and body.get('mode') == 'formdata':
            for f in body.get('formdata', []):
                 if not f.get('disabled') and f.get('key'):
                     parameters.append({
                        "name": f['key'],
                         "in": "formData",
                         "schema": {"type": "string", "default": f.get('value', '')},
                         "description": "Postman Form Data"
                     })
        elif body and body.get('mode') == 'urlencoded':
             for f in body.get('urlencoded', []):
                 if not f.get('disabled') and f.get('key'):
                     parameters.append({
                        "name": f['key'],
                         "in": "formData",
                         "schema": {"type": "string", "default": f.get('value', '')},
                         "description": "Postman UrlEncoded"
                     })

        return APIEndpoint(
            path=path,
            method=method,
            summary=name,
            parameters=parameters,
            request_body_schema=request_body_schema
        )
