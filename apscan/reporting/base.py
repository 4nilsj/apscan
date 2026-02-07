from abc import ABC, abstractmethod
from typing import List
from apscan.core.context import Vulnerability, ScanContext

class Reporter(ABC):
    @abstractmethod
    def generate(self, context: ScanContext):
        """Generates a report from the scan context."""
        pass
