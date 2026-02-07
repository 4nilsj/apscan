import unittest
from unittest.mock import MagicMock, AsyncMock
from apscan.core.context import APIEndpoint, HttpMethod, ScanContext, ScanTarget, Severity, ScanResponse
# Import Rules
from apscan.rules.owasp.open_redirect import OpenRedirectRule
from apscan.rules.config.shadow_api import ShadowAPIRule
from apscan.rules.data_exposure.pii import PIIExposureRule
from apscan.rules.data_exposure.stack_trace import StackTraceRule
from apscan.rules.config.unsafe_methods import UnsafeMethodsRule
from apscan.rules.injection.prototype_pollution import PrototypePollutionRule

class TestAdvancedRules(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.target = ScanTarget(url="http://example.com")
        self.mock_client = MagicMock()
        self.context = ScanContext(self.target, self.mock_client)

    # --- Open Redirect ---
    async def test_open_redirect_detected(self):
        rule = OpenRedirectRule()
        endpoint = APIEndpoint(
            path="/login", 
            method=HttpMethod.GET,
            parameters=[{"name": "next", "in": "query", "schema": {"type": "string"}}]
        )
        
        # Mock Redirect Response
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://evil.com"}
        mock_resp.body = ""
        mock_resp.elapsed_time = 0.1
        
        self.mock_client.send = AsyncMock(return_value=mock_resp)
        
        findings = await rule.run(endpoint, self.context)
        self.assertEqual(len(findings), 1)
        self.assertIn("Open Redirect", findings[0].name)

    async def test_open_redirect_safe(self):
        rule = OpenRedirectRule()
        endpoint = APIEndpoint(
            path="/login", 
            method=HttpMethod.GET,
            parameters=[{"name": "next", "in": "query"}]
        )
        
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "/home"} # Safe
        mock_resp.body = ""
        
        self.mock_client.send = AsyncMock(return_value=mock_resp)
        findings = await rule.run(endpoint, self.context)
        self.assertEqual(len(findings), 0)

    # --- Shadow API ---
    async def test_shadow_api_detected(self):
        rule = ShadowAPIRule()
        endpoint = APIEndpoint(path="/users", method=HttpMethod.GET)
        
        # Mock existence check
        # We need to simulate that specific guesses return 200 OK
        # _check_exists calls http_client.send. 
        # Logic: if url ends with "/v1" or "/old" etc.
        
        async def side_effect(req):
            resp = MagicMock()
            if "/old" in req.url:
                resp.status_code = 200
            else:
                resp.status_code = 404
            return resp
            
        self.mock_client.send = AsyncMock(side_effect=side_effect)
        
        findings = await rule.run(endpoint, self.context)
        # Should find at least one (e.g. /old)
        self.assertTrue(len(findings) > 0)
        self.assertIn("Shadow API", findings[0].name)

    # --- PII Exposure ---
    async def test_pii_exposure_detected(self):
        rule = PIIExposureRule()
        endpoint = APIEndpoint(path="/users/1", method=HttpMethod.GET)
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.body = '{"email": "victim@example.com", "ssn": "123-45-6789"}'
        
        self.mock_client.send = AsyncMock(return_value=mock_resp)
        
        findings = await rule.run(endpoint, self.context)
        # Expect EMAIL and SSN
        self.assertTrue(len(findings) >= 2) 

    # --- Stack Trace ---
    async def test_stack_trace_detected(self):
        rule = StackTraceRule()
        endpoint = APIEndpoint(path="/api/data", method=HttpMethod.POST)
        
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.body = "Internal Server Error: Traceback (most recent call last):\n File app.py line 1"
        
        self.mock_client.send = AsyncMock(return_value=mock_resp)
        
        findings = await rule.run(endpoint, self.context)
        # Expect 2 findings: one for malformed body, one for invalid params
        self.assertEqual(len(findings), 2)
        self.assertIn("Stack Trace", findings[0].name)

    # --- Unsafe Methods ---
    async def test_unsafe_methods_detected(self):
        rule = UnsafeMethodsRule()
        endpoint = APIEndpoint(path="/api/test", method=HttpMethod.GET)
        
        async def side_effect(req):
            resp = MagicMock()
            resp.status_code = 200
            if req.method == HttpMethod.TRACE:
                resp.body = str(req.headers) # Reflected
                # Mock headers on request for context
                # The rule checks req.headers.get("User-Agent") in body
                # Mock request object passed in scan request
                pass 
            else:
                resp.body = "OK"
            return resp
            
        self.mock_client.send = AsyncMock(side_effect=side_effect)
        
        findings = await rule.run(endpoint, self.context)
        # Expect TRACE, TRACK, CONNECT. If logic finds all enabled.
        self.assertTrue(len(findings) > 0)
        self.assertIn("Unsafe HTTP Methods", findings[0].name)

    # --- Prototype Pollution ---
    async def test_prototype_pollution_detected(self):
        rule = PrototypePollutionRule()
        endpoint = APIEndpoint(path="/api/update", method=HttpMethod.POST)
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.body = '{"__proto__": {"polluted": "true"}, "success": true}'
        
        self.mock_client.send = AsyncMock(return_value=mock_resp)
        
        findings = await rule.run(endpoint, self.context)
        self.assertEqual(len(findings), 1)
        self.assertIn("Prototype Pollution", findings[0].name)
