import pytest
from apscan.core.request_engine import RequestFactory
from apscan.core.context import APIEndpoint, HttpMethod

def test_create_request_simple():
    endpoint = APIEndpoint(
        path="/users",
        method=HttpMethod.GET,
        parameters=[]
    )
    req = RequestFactory.create_request(endpoint)
    
    assert req.method == HttpMethod.GET
    assert req.url == "/users"
    assert req.params == {}
    assert req.headers == {}

def test_create_request_with_query_params():
    endpoint = APIEndpoint(
        path="/search",
        method=HttpMethod.GET,
        parameters=[
            {"name": "q", "in": "query", "schema": {"type": "string"}},
            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
        ]
    )
    req = RequestFactory.create_request(endpoint)
    
    # "test_value" and 1 are default values from logic
    assert req.params["q"] == "test_value" 
    assert req.params["limit"] == 1

def test_create_request_with_header_params():
    endpoint = APIEndpoint(
        path="/admin",
        method=HttpMethod.GET,
        parameters=[
            {"name": "X-Admin", "in": "header", "schema": {"type": "boolean"}}
        ]
    )
    req = RequestFactory.create_request(endpoint)
    
    # boolean true is default
    assert req.headers["X-Admin"] == "True"

def test_create_request_with_path_params():
    endpoint = APIEndpoint(
        path="/users/{id}",
        method=HttpMethod.GET,
        parameters=[
            {"name": "id", "in": "path", "schema": {"type": "integer"}}
        ]
    )
    req = RequestFactory.create_request(endpoint)
    
    assert req.url == "/users/1"

def test_create_request_with_payload_override():
    endpoint = APIEndpoint(
        path="/users",
        method=HttpMethod.POST,
        parameters=[
            {"name": "username", "in": "query"}
        ]
    )
    payload = {"username": "admin"}
    req = RequestFactory.create_request(endpoint, payload=payload)
    
    assert req.params["username"] == "admin"
