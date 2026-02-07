from abc import ABC, abstractmethod
from typing import Dict

class AuthProvider(ABC):
    @abstractmethod
    def get_headers(self) -> Dict[str, str]:
        """Returns the headers required for authentication."""
        pass
