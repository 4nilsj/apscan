import pytest
from apscan.core.context import ScanContext, ScanTarget, APIEndpoint, HttpMethod, Vulnerability, Severity

def test_scan_target_initialization():
    target = ScanTarget(url="http://example.com")
    assert target.url == "http://example.com"
    assert target.headers == {}

def test_api_endpoint_initialization():
    endpoint = APIEndpoint(
        path="/users",
        method=HttpMethod.GET,
        parameters=[]
    )
    assert endpoint.path == "/users"
    assert endpoint.method == HttpMethod.GET

def test_vulnerability_validation():
    vuln = Vulnerability(
        rule_id="TEST-001",
        name="Test",
        severity=Severity.HIGH,
        description="Desc",
        endpoint="/test",
        method=HttpMethod.GET,
        evidence="Evidence"
    )
    assert vuln.severity == Severity.HIGH

def test_scan_context_initialization():
    target = ScanTarget(url="http://example.com")
    context = ScanContext(target=target)
    
    assert context.target == target
    assert context.findings == []
    assert context.auth_headers == {}
