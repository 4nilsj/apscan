import pytest
from apscan.core.context import ScanContext, APIEndpoint, HttpMethod, ScanTarget
from apscan.rules.data_exposure.secrets import SecretsExposureRule
from apscan.rules.config.dependency_check import DependencyCheckRule

class MockResponse:
    def __init__(self, status_code: int = 200, headers: dict = None, body: str = ""):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        self.text = body

class MockHTTPClient:
    def __init__(self):
        self.responses = {}

    def add_response(self, method: str, path: str, status: int = 200, headers: dict = None, body: str = ""):
        # Normalize key for test simplicity
        key = (method.upper(), path)
        self.responses[key] = MockResponse(status, headers, body)

    async def send(self, request):
        # Extract path from full URL for matching
        full_url = str(request.url)
        path = "/" + full_url.split("test.com/")[-1] 
        if path.startswith("//"): path = path[1:] # Fix potential double slash
        if path == "/test.com": path = "/" # Fix root case if strict split fails

        key = (request.method.upper(), path)
        
        if key in self.responses:
            return self.responses[key]
        
        # Fallback debug
        # print(f"Mock Client: No match for {key}. Available: {list(self.responses.keys())}")
        return MockResponse(404, {}, "")


@pytest.mark.asyncio
async def test_secrets_exposure_aws_key():
    rule = SecretsExposureRule()
    endpoint = APIEndpoint(method=HttpMethod.GET, path="/api/config")
    
    # Mock Response with AWS Key
    mock_client = MockHTTPClient()
    mock_client.add_response("GET", "/api/config", status=200, body='{"aws_key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}')
    
    target = ScanTarget(url="http://test.com")
    context = ScanContext(target=target, http_client=mock_client)
    
    findings = await rule.run(endpoint, context)
    
    assert len(findings) >= 1
    assert "AWS Access Key Exposure" in [f.name for f in findings]
    assert findings[0].severity.value == "CRITICAL"

@pytest.mark.asyncio
async def test_secrets_exposure_no_secrets():
    rule = SecretsExposureRule()
    endpoint = APIEndpoint(method=HttpMethod.GET, path="/api/safe")
    
    # Mock Safe Response
    mock_client = MockHTTPClient()
    mock_client.add_response("GET", "/api/safe", status=200, body='{"message": "Hello World"}')
    
    target = ScanTarget(url="http://test.com")
    context = ScanContext(target=target, http_client=mock_client)
    
    findings = await rule.run(endpoint, context)
    
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_dependency_check_header():
    rule = DependencyCheckRule()
    endpoint = APIEndpoint(method=HttpMethod.GET, path="/")
    
    # Mock Response with Version Header
    mock_client = MockHTTPClient()
    mock_client.add_response("GET", "/", status=200, headers={"X-Powered-By": "Express/4.17.1"})
    
    target = ScanTarget(url="http://test.com")
    context = ScanContext(target=target, http_client=mock_client)
    
    findings = await rule.run(endpoint, context)
    
    assert len(findings) >= 1
    assert "Leaked Version Header: X-Powered-By" in [f.name for f in findings]

@pytest.mark.asyncio
async def test_dependency_check_config_file():
    rule = DependencyCheckRule()
    endpoint = APIEndpoint(method=HttpMethod.GET, path="/")
    
    # Mock Response for root and package.json
    mock_client = MockHTTPClient()
    mock_client.add_response("GET", "/", status=200)
    mock_client.add_response("GET", "/package.json", status=200, body='{"dependencies": {"react": "18.0.0"}}')
    
    target = ScanTarget(url="http://test.com")
    context = ScanContext(target=target, http_client=mock_client)
    
    findings = await rule.run(endpoint, context)
    
    # Should find package.json exposure
    assert len(findings) >= 1
    assert "Exposed Configuration File: /package.json" in [f.name for f in findings]
