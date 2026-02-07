import yaml
from typing import Dict, Any
from apscan.core.workflow import Workflow

class WorkflowLoader:
    def load(self, file_path: str) -> Workflow:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
            return Workflow(**data)
