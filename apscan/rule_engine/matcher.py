from typing import Dict, Any, Union, Optional
import re
from apscan.core.context import ScanResponse

class DetectionMatcher:
    """
    Evaluates response against a set of match criteria.
    Supports: exact status, body substring/regex, header presence/value.
    """
    def __init__(self, criteria: Dict[str, Any]):
        self.criteria = criteria

    def matches(self, response: ScanResponse) -> bool:
        if not self.criteria:
            return False

        # 1. Status Code
        if "status" in self.criteria:
            expected_status = self.criteria["status"]
            if isinstance(expected_status, list):
                if response.status_code not in expected_status:
                    return False
            elif response.status_code != expected_status:
                return False

        # 2. Body Text (Simple contains) - Case Insensitive
        if "body" in self.criteria:
            if self.criteria["body"].lower() not in response.body.lower():
                return False

        # 3. Negative Match (response_not_contains)
        if "response_not_contains" in self.criteria:
            for word in self.criteria["response_not_contains"]:
                if word.lower() in response.body.lower():
                    return False

        # 4. Body Regex
        if "body_regex" in self.criteria:
            pattern = self.criteria["body_regex"]
            if not re.search(pattern, response.body):
                return False

        # 5. Headers
        if "headers" in self.criteria:
            for name, value in self.criteria["headers"].items():
                header_val = self._get_header(response.headers, name)
                if header_val is None:
                    return False
                if value and value not in header_val:
                    return False
        
        return True

    def _get_header(self, headers: Dict[str, str], key: str) -> Optional[str]:
        key_lower = key.lower()
        for k, v in headers.items():
            if k.lower() == key_lower:
                return v
        return None
