import unittest
from unittest.mock import MagicMock, AsyncMock
from apscan.rules.owasp.cors import CORSRule
from apscan.core.context import APIEndpoint, HttpMethod, ScanContext, ScanTarget, Severity

class TestCORSRule(unittest.IsolatedAsyncioTestCase):
    async def test_cors_vulnerability_detected(self):
        rule = CORSRule()
        
        # Mock Context & HTTP Client
        target = ScanTarget(url="http://example.com")
        mock_client = MagicMock()
        context = ScanContext(target, mock_client)
        context.auth_headers = {}
        
        # Mock Response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Access-Control-Allow-Origin": "http://evil.com",
            "Access-Control-Allow-Credentials": "true"
        }
        mock_client.send = AsyncMock(return_value=mock_response)
        
        # Endpoint
        endpoint = APIEndpoint(path="/test", method=HttpMethod.GET)
        
        # Run Rule
        findings = await rule.run(endpoint, context)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Cross-Origin", findings[0].description)

    async def test_cors_secure(self):
        rule = CORSRule()
        
        # Mock Context
        target = ScanTarget(url="http://example.com")
        mock_client = MagicMock()
        context = ScanContext(target, mock_client)
        context.auth_headers = {}
        
        # Mock Response (Secure: ignores Origin or reflects without Credentials)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Access-Control-Allow-Origin": "http://example.com", # Trusted
            "Access-Control-Allow-Credentials": "true"
        }
        mock_client.send = AsyncMock(return_value=mock_response)
        
        endpoint = APIEndpoint(path="/test", method=HttpMethod.GET)
        
        findings = await rule.run(endpoint, context)
        self.assertEqual(len(findings), 0)
