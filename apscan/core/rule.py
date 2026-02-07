from abc import ABC, abstractmethod
from typing import List
from apscan.core.context import APIEndpoint, Vulnerability, ScanContext
from apscan.core.request_engine import RequestFactory

class ScannerRule(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def run(self, endpoint: APIEndpoint, context: ScanContext) -> List[Vulnerability]:
        """
        Runs the rule against a specific endpoint.
        The context provides shared memory (findings, auth headers) and resources (http_client).
        """
        pass
