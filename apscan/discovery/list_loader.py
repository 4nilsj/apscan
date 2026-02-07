from typing import List
from urllib.parse import urlparse
from apscan.core.context import APIEndpoint, HttpMethod

class ListLoader:
    """Parses a text file containing URLs into APIEndpoints."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path

    def load(self) -> List[APIEndpoint]:
        endpoints = []
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[!] Error loading List file: {e}")
            return []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check for METHOD URL format
            parts = line.split()
            if len(parts) >= 2 and parts[0].upper() in HttpMethod.__members__:
                method = HttpMethod[parts[0].upper()]
                url = parts[1]
            else:
                method = HttpMethod.GET
                url = parts[0]
                # If URL doesn't start with http, ignore or assume http?
                if not url.startswith('http'):
                     # Skip invalid lines
                     continue

            parsed = urlparse(url)
            path = parsed.path
            
            parameters = []
            if parsed.query:
                from urllib.parse import parse_qs
                qs = parse_qs(parsed.query)
                for k, v in qs.items():
                    val = v[0] if v else ""
                    parameters.append({
                        "name": k,
                        "in": "query", 
                        "schema": {"type": "string", "default": val},
                        "description": "From List URL"
                    })

            endpoints.append(APIEndpoint(
                path=path,
                method=method,
                summary=f"Imported from List: {url}",
                parameters=parameters,
                request_body_schema=None
            ))
            
        return endpoints
