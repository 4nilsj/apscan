from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class Extraction(BaseModel):
    """
    Defines how to extract a value from a response.
    """
    source: str = "body" # "body", "header", "cookie"
    key: Optional[str] = None # JSON key (dot notation) or Header name
    regex: Optional[str] = None # Regex with capture group
    variable: str # Name of variable to save to

class WorkflowStep(BaseModel):
    """
    A single step in a workflow.
    """
    id: str
    method: str
    path: str # Can contain ${var}
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None # Can contain ${var}
    files: Optional[Dict[str, Any]] = None # For multipart uploads
    params: Dict[str, Any] = Field(default_factory=dict)
    extract: List[Extraction] = Field(default_factory=list)
    scan: bool = True # IF true, run enabled security rules on this request

class Workflow(BaseModel):
    """
    A sequence of steps defining a stateful test scenario.
    """
    id: str
    name: str
    description: Optional[str] = None
    steps: List[WorkflowStep]
