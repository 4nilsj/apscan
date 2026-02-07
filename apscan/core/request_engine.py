from typing import Any, Dict, List
from apscan.core.context import APIEndpoint, ScanRequest

class RequestFactory:
    """Generates ScanRequests from APIEndpoints."""

    @staticmethod
    def create_request(endpoint: APIEndpoint, payload: Dict[str, Any] = None, exclude_params: List[str] = None) -> ScanRequest:
        """
        Creates a ScanRequest for the given endpoint.
        If payload is provided, it overrides default parameter generation.
        exclude_params: list of parameter names to skip (e.g. for auth bypass tests)
        """
        url = endpoint.path 
        method = endpoint.method
        
        # simplified parameter handling for MVP
        params = {}
        headers = {}
        json_body = {}
        exclude_params = exclude_params or []

        # Default payload generation if not provided
        if not payload:
            payload = {}
        
        # Populate based on parameter location
        for param in endpoint.parameters:
            name = param.get('name')
            if name in exclude_params:
                continue
                
            in_loc = param.get('in')
            schema = param.get('schema', {})
            param_type = schema.get('type', 'string')
            
            # Smart default based on type
            if param_type == 'integer':
                default_val = 1
            elif param_type == 'boolean':
                default_val = True
            else:
                default_val = "test_value"
                
            value = payload.get(name, default_val)
            
            if in_loc == 'query':
                params[name] = value
            elif in_loc == 'header':
                headers[name] = str(value)
            elif in_loc == 'path':
                # Path params validation
                url = url.replace(f"{{{name}}}", str(value))
        
        # Body handling
        if endpoint.request_body_schema:
            json_body = {"dummy": "data"} 

        return ScanRequest(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_body=json_body,
            meta={"excluded": exclude_params}
        )
