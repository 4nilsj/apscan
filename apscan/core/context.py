from typing import List, Dict, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    TRACK = "TRACK"
    CONNECT = "CONNECT"

class APIEndpoint(BaseModel):
    """Represents a discovered API Endpoint."""
    path: str
    method: HttpMethod
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None

    class Config:
        frozen = True

class ScanRequest(BaseModel):
    """Represents a request to be sent to the target."""
    method: HttpMethod
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    json_body: Optional[Any] = None
    data: Optional[Any] = None
    files: Optional[Dict[str, Any]] = None # For multipart/form-data
    cookies: Dict[str, str] = Field(default_factory=dict)
    
    # Metadata for the scanner to know what was mutated
    meta: Dict[str, Any] = Field(default_factory=dict)

class ScanResponse(BaseModel):
    """Represents the response from the target."""
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float

class Vulnerability(BaseModel):
    """Represents a security finding."""
    rule_id: str
    name: str = "Unknown" # Default if not provided
    severity: Severity
    description: str
    impact: str = "Unknown" # New field
    endpoint: str
    method: HttpMethod
    evidence: str
    recommendation: Optional[str] = None # Renamed from remediation
    confidence: str = "MEDIUM" # LOW, MEDIUM, HIGH
    
    # Detailed Evidence
    reproduce_curl: Optional[str] = None
    request_details: Optional[Dict[str, Any]] = None
    response_details: Optional[Dict[str, Any]] = None

    # AI Enrichment
    ai_analysis: Optional[str] = None
    ai_confidence: Optional[str] = None

class ScanTarget(BaseModel):
    """Configuration for the target to be scanned."""
    url: Optional[str] = None 
    curl_command: Optional[str] = None
    har_file: Optional[str] = None
    postman_file: Optional[str] = None
    list_file: Optional[str] = None
    plugin_dir: Optional[str] = None
    graphql: bool = False
    auth_config: Optional[Dict[str, Any]] = None
    ai_config: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = Field(default_factory=dict)

# New Shared Context Class
class ScanContext:
    def __init__(self, target: ScanTarget, http_client: Any = None):
        self.target = target
        self.http_client = http_client # Added dependency injection here
        self.endpoints: List[APIEndpoint] = []
        self.auth_headers: Dict[str, str] = {}
        self.findings: List[Vulnerability] = []
        self.scanned_hashes = set()
        
        # Helper accessor for rules
        self.target_url = target.url
        
        # Stateful Workflow Context
        self.variables: Dict[str, Any] = {}
