from typing import Dict
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
