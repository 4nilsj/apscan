from abc import ABC, abstractmethod
from apscan.core.context import Vulnerability

class AIProvider(ABC):
    @abstractmethod
    def analyze_finding(self, finding: Vulnerability) -> str:
        """
        Analyzes a single vulnerability finding and returns a detailed explanation 
        and remediation advice.
        """
        pass
