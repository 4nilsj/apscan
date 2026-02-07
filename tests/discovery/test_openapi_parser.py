import pytest
from unittest.mock import patch, mock_open, MagicMock
from apscan.discovery.openapi_parser import OpenAPILoader
from apscan.core.context import HttpMethod

# Mock OpenAPI Spec
VALID_SPEC = """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      summary: List users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              properties:
                username:
                  type: string
                email:
                  type: string
"""

def test_load_from_url_success():
    with patch("httpx.get") as mock_get:
        mock_response = MagicMock()
        mock_response.text = VALID_SPEC
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        loader = OpenAPILoader("http://example.com/openapi.yaml")
        endpoints = loader.load()

        assert len(endpoints) == 2
        assert endpoints[0].path == "/users"
        assert endpoints[0].method in [HttpMethod.GET, HttpMethod.POST]

def test_load_from_url_failure():
    with patch("httpx.get") as mock_get:
        mock_get.side_effect = Exception("Connection Error")

        loader = OpenAPILoader("http://example.com/openapi.yaml")
        endpoints = loader.load()

        assert len(endpoints) == 0

def test_load_from_file_success():
    with patch("builtins.open", mock_open(read_data=VALID_SPEC)):
        loader = OpenAPILoader("openapi.yaml")
        endpoints = loader.load()

        assert len(endpoints) == 2

def test_parse_endpoints_structure():
    with patch("builtins.open", mock_open(read_data=VALID_SPEC)):
        loader = OpenAPILoader("openapi.yaml")
        endpoints = loader.load()
        
        # Sort by method to ensure deterministic checks
        endpoints.sort(key=lambda x: x.method)
        # GET comes before POST
        
        # Check GET /users
        get_endpoint = next(e for e in endpoints if e.method == HttpMethod.GET)
        assert get_endpoint.path == "/users"
        assert len(get_endpoint.parameters) == 1
        assert get_endpoint.parameters[0]['name'] == 'limit'
        
        # Check POST /users
        post_endpoint = next(e for e in endpoints if e.method == HttpMethod.POST)
        assert post_endpoint.path == "/users"
        # 2 properties in body -> 2 parameters
        assert len(post_endpoint.parameters) == 2 
        param_names = [p['name'] for p in post_endpoint.parameters]
        assert "username" in param_names
        assert "email" in param_names
