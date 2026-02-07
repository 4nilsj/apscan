from typing import Dict, Optional
import requests
from apscan.auth.base import AuthProvider

class ApiKeyAuth(AuthProvider):
    def __init__(self, key: str, header: str):
        self.key = key
        self.header = header

    def get_headers(self) -> Dict[str, str]:
        return {self.header: self.key}

class BasicAuth(AuthProvider):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        
    def get_headers(self) -> Dict[str, str]:
        import base64
        creds = f"{self.username}:{self.password}"
        token = base64.b64encode(creds.encode()).decode()
        return {"Authorization": f"Basic {token}"}

class BearerAuth(AuthProvider):
    def __init__(self, token: str):
        self.token = token
        
    def get_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

class CookieAuth(AuthProvider):
    def __init__(self, cookie_string: str):
        self.cookie_string = cookie_string
        
    def get_headers(self) -> Dict[str, str]:
        return {"Cookie": self.cookie_string}

class OAuth2ClientCredentials(AuthProvider):
    def __init__(self, token_url: str, client_id: str, client_secret: str, scope: Optional[str] = None):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._token = None
        
    def _fetch_token(self) -> str:
        try:
            payload = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            if self.scope:
                payload["scope"] = self.scope
                
            response = requests.post(self.token_url, data=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("access_token")
        except Exception as e:
            print(f"[!] OAuth2 Token Fetch Failed: {e}")
            return ""

    def get_headers(self) -> Dict[str, str]:
        if not self._token:
            self._token = self._fetch_token()
            
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}
