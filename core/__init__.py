"""Core module for AEM Offensive Framework.

Contains data models, configuration, and the async HTTP engine.
Note: core.phases is NOT imported here to avoid circular imports
      (core -> phases -> bypass -> core). Import phases directly:
      from core.phases import PhaseManager
"""

from .models import (
    Finding,
    TargetInfo,
    AttackPath,
    ScanResult,
    ServerType,
    VulnSeverity,
    BypassTechnique,
    ScanPhase,
    RequestConfig,
    RateLimitConfig,
)

from .config import AEMConfig, DEFAULT_HEADERS, USER_AGENTS, X_FORWARDED_IPS

from .engine import HTTPXEngine, AdaptiveRateLimiter, ResponseWrapper

__all__ = [
    "Finding",
    "TargetInfo",
    "AttackPath",
    "ScanResult",
    "ServerType",
    "VulnSeverity",
    "BypassTechnique",
    "ScanPhase",
    "RequestConfig",
    "RateLimitConfig",
    "AEMConfig",
    "DEFAULT_HEADERS",
    "USER_AGENTS",
    "X_FORWARDED_IPS",
    "HTTPXEngine",
    "AdaptiveRateLimiter",
    "ResponseWrapper",
]
