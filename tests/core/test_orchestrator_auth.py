import pytest
import asyncio
from unittest.mock import MagicMock, patch
from apscan.core.orchestrator import ScanOrchestrator
from apscan.core.context import ScanTarget

@pytest.mark.asyncio
async def test_orchestrator_bearer_auth():
    target = ScanTarget(
        url="http://test.com",
        auth_config={"type": "bearer", "token": "my-secret-token"}
    )
    orchestrator = ScanOrchestrator(target)
    
    # Run authentication step
    await orchestrator.authenticate()
    
    # Verify context has auth headers
    assert "Authorization" in orchestrator.context.auth_headers
    assert orchestrator.context.auth_headers["Authorization"] == "Bearer my-secret-token"

@pytest.mark.asyncio
async def test_orchestrator_cookie_auth():
    target = ScanTarget(
        url="http://test.com",
        auth_config={"type": "cookie", "cookie": "session=abc"}
    )
    orchestrator = ScanOrchestrator(target)
    
    await orchestrator.authenticate()
    
    assert "Cookie" in orchestrator.context.auth_headers
    assert orchestrator.context.auth_headers["Cookie"] == "session=abc"

@pytest.mark.asyncio
async def test_orchestrator_oauth2_auth():
    target = ScanTarget(
        url="http://test.com",
        auth_config={
            "type": "oauth2",
            "token_url": "http://auth.com/token",
            "client_id": "cid",
            "client_secret": "csecret"
        }
    )
    
    # Mock external request inside the provider
    with patch("apscan.auth.providers.requests.post") as mock_post:
        mock_post.return_value.json.return_value = {"access_token": "oauth-token"}
        mock_post.return_value.raise_for_status.return_value = None
        
        orchestrator = ScanOrchestrator(target)
        await orchestrator.authenticate()
        
        assert "Authorization" in orchestrator.context.auth_headers
        assert orchestrator.context.auth_headers["Authorization"] == "Bearer oauth-token"
