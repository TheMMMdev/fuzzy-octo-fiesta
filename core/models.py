"""Core data models for AEM Offensive Framework using Pydantic v2."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field, HttpUrl


class ServerType(str, Enum):
    """AEM server type classification."""
    AUTHOR = "author"
    PUBLISH = "publish"
    UNKNOWN = "unknown"


class VulnSeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BypassTechnique(str, Enum):
    """Dispatcher bypass techniques."""
    SEMICOLON = "semicolon_injection"
    DOUBLE_EXTENSION = "double_extension"
    SELECTOR_SMUGGLING = "selector_smuggling"
    NULL_BYTE = "null_byte"
    URL_ENCODING = "url_encoding"
    DOUBLE_ENCODING = "double_encoding"
    PATH_TRAVERSAL = "path_traversal"
    UNICODE = "unicode_normalization"
    CASE_SENSITIVITY = "case_sensitivity"
    SEMICOLON_GAP = "semicolon_gap"
    PATH_OVERLAP = "path_overlap"
    SLING_SUFFIX = "sling_suffix"
    JCR_CONTENT = "jcr_content"
    QUERY_EXTENSION = "query_extension"


class ScanPhase(str, Enum):
    """Scan execution phases."""
    FINGERPRINTING = "fingerprinting"
    DISCOVERY = "discovery"
    EXPLOITATION = "exploitation"


class Finding(BaseModel):
    """Represents a security finding."""
    id: str = Field(default_factory=lambda: f"F{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
    phase: ScanPhase
    technique: str
    url: str
    severity: VulnSeverity
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    bypass_used: Optional[BypassTechnique] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    chainable: bool = Field(default=False, description="Can be chained with other findings")
    prerequisites: List[str] = Field(default_factory=list)


class TargetInfo(BaseModel):
    """Target fingerprinting information."""
    url: str
    server_type: ServerType = ServerType.UNKNOWN
    aem_version: Optional[str] = None
    dispatcher_rules: Dict[str, Any] = Field(default_factory=dict)
    detected_paths: Set[str] = Field(default_factory=set)
    blocked_patterns: List[str] = Field(default_factory=list)
    allowed_selectors: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """Represents a chainable attack path."""
    id: str
    name: str
    description: str
    findings: List[Finding]
    entry_point: str
    impact: str
    complexity: str


class ScanResult(BaseModel):
    """Complete scan results."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    target_info: TargetInfo
    findings: List[Finding] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    statistics: Dict[str, int] = Field(default_factory=dict)
    raw_responses: Dict[str, Any] = Field(default_factory=dict)


class RequestConfig(BaseModel):
    """Request configuration with WAF evasion."""
    headers: Dict[str, str] = Field(default_factory=dict)
    timeout: float = 30.0
    follow_redirects: bool = True
    verify_ssl: bool = False
    proxy: Optional[str] = None


class RateLimitConfig(BaseModel):
    """Adaptive rate limiting configuration."""
    base_delay: float = 1.0
    max_delay: float = 10.0
    min_delay: float = 0.5
    burst_size: int = 5
    adaptive: bool = True
    jitter: bool = True
