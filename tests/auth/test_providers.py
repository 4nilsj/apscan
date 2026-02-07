import pytest
from unittest.mock import patch, Mock
from apscan.auth.providers import BearerAuth, CookieAuth, OAuth2ClientCredentials

def test_bearer_auth():
    auth = BearerAuth("my-token")
    headers = auth.get_headers()
    assert headers == {"Authorization": "Bearer my-token"}

def test_cookie_auth():
    auth = CookieAuth("session=123")
    headers = auth.get_headers()
    assert headers == {"Cookie": "session=123"}

def test_oauth2_client_credentials_success():
    with patch("apscan.auth.providers.requests.post") as mock_post:
        # Mock successful token response
        mock_response = Mock()
        mock_response.json.return_value = {"access_token": "mock-access-token", "token_type": "Bearer"}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        auth = OAuth2ClientCredentials(
            token_url="https://auth.example.com/token",
            client_id="client-id",
            client_secret="client-secret",
            scope="read"
        )
        
        headers = auth.get_headers()
        
        assert headers == {"Authorization": "Bearer mock-access-token"}
        
        # Verify call arguments
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://auth.example.com/token"
        assert kwargs["data"] == {
            "grant_type": "client_credentials",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "scope": "read"
        }

def test_oauth2_client_credentials_failure():
    with patch("apscan.auth.providers.requests.post") as mock_post:
        # Mock failed response
        mock_post.side_effect = Exception("Connection Error")

        auth = OAuth2ClientCredentials(
            token_url="https://auth.example.com/token",
            client_id="client-id",
            client_secret="client-secret"
        )
        
        headers = auth.get_headers()
        
        # Should return empty dict on failure without crashing
        assert headers == {}
