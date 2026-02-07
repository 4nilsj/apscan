from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from apscan.core.context import Vulnerability

class ScanInputType(str, Enum):
    OPENAPI = "openapi"
    CURL = "curl"
    HAR = "har"
    POSTMAN = "postman"
    LIST = "list"
    WORKFLOW = "workflow"

class AuthType(str, Enum):
    NONE = "none"
    BASIC = "basic"
    APIKEY = "apikey"

class ScanConfigRequest(BaseModel):
    """Configuration payload for starting a scan."""
    input_type: ScanInputType
    target_url: Optional[str] = None # For OpenAPI
    curl_command: Optional[str] = None
    file_content: Optional[str] = None # For HAR/Postman/List/OpenAPI-File (text content)
    
    # Auth
    auth_type: AuthType = AuthType.NONE
    auth_key: Optional[str] = None
    auth_header: Optional[str] = "X-API-Key"
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None

    # Advanced
    graphql: bool = False
    ai_provider: Optional[str] = None # gemini, openai, local
    ai_key: Optional[str] = None
    ai_model: Optional[str] = None

class ScanState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanStatusResponse(BaseModel):
    id: str
    state: ScanState
    message: str
    endpoints_count: int = 0
    findings_count: int = 0
    progress: int = 0 

class ScanSubmissionResponse(BaseModel):
    scan_id: str
    message: str
