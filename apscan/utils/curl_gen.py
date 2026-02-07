from typing import Any, Dict
from apscan.core.context import ScanRequest

def generate_curl_command(req: ScanRequest) -> str:
    """Generates a cURL command string from a ScanRequest."""
    method = req.method.value
    url = req.url
    
    cmd = [f"curl -X {method} '{url}'"]
    
    for k, v in req.headers.items():
        cmd.append(f"-H '{k}: {v}'")
        
    if req.json_body:
        import json
        body = json.dumps(req.json_body)
        cmd.append(f"-d '{body}'")
    elif req.data:
        cmd.append(f"-d '{req.data}'")
        
    return " ".join(cmd)
