import unittest
from unittest.mock import MagicMock, AsyncMock
from apscan.rules.auth.method_tampering import MethodTamperingRule
from apscan.core.context import APIEndpoint, HttpMethod, ScanContext, ScanTarget, Severity

class TestMethodTamperingRule(unittest.IsolatedAsyncioTestCase):
    async def test_method_bypass_detected(self):
        rule = MethodTamperingRule()
        
        target = ScanTarget(url="http://example.com")
        mock_client = MagicMock()
        context = ScanContext(target, mock_client)
        
        # Mock Responses
        # First call: GET (Base) -> 401 Unauthorized
        # Second call: HEAD -> 200 OK (Bypass)
        
        mock_resp_base = MagicMock()
        mock_resp_base.status_code = 401
        
        mock_resp_head = MagicMock()
        mock_resp_head.status_code = 200
        
        mock_client.send = AsyncMock(side_effect=[mock_resp_base, mock_resp_head])
        
        endpoint = APIEndpoint(path="/admin", method=HttpMethod.GET)
        
        findings = await rule.run(endpoint, context)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("allows HEAD", findings[0].description)

    async def test_no_bypass_if_base_is_ok(self):
        rule = MethodTamperingRule()
        
        target = ScanTarget(url="http://example.com")
        mock_client = MagicMock()
        context = ScanContext(target, mock_client)
        
        # If Base GET is 200 OK (Public), we can't determine bypass
        mock_resp_base = MagicMock()
        mock_resp_base.status_code = 200
        
        mock_client.send = AsyncMock(return_value=mock_resp_base)
        
        endpoint = APIEndpoint(path="/public", method=HttpMethod.GET)
        
        findings = await rule.run(endpoint, context)
        self.assertEqual(len(findings), 0)

    async def test_secure_endpoint_blocks_both(self):
        rule = MethodTamperingRule()
        
        target = ScanTarget(url="http://example.com")
        mock_client = MagicMock()
        context = ScanContext(target, mock_client)
        
        # Base GET -> 401
        # HEAD -> 401 (Secure)
        mock_resp_base = MagicMock()
        mock_resp_base.status_code = 401
        
        mock_resp_head = MagicMock()
        mock_resp_head.status_code = 401
        
        mock_client.send = AsyncMock(side_effect=[mock_resp_base, mock_resp_head])
        
        endpoint = APIEndpoint(path="/admin", method=HttpMethod.GET)
        
        findings = await rule.run(endpoint, context)
        self.assertEqual(len(findings), 0)
