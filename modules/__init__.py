"""Testing modules for AEM Offensive Framework.

Contains security testing modules:
- JCR Probing
- OSGi Exploitation  
- Injection Testing
- CVE Suite
- Sling Smuggler
- JCR Inference Engine
- Service Probe
"""

from .jcr_probe import JCRProbingModule, JCRNode
from .osgi_exploit import OSGiExploitationModule, OSGiConsole
from .injection import InjectionTestingModule, InjectionPayload
from .cve_suite import CVESuiteModule, CVECheck
from .sling_smuggler import SlingSmuggler
from .jcr_inference import JCRInferenceEngine
from .service_probe import ServiceProbeModule

__all__ = [
    "JCRProbingModule",
    "JCRNode",
    "OSGiExploitationModule",
    "OSGiConsole",
    "InjectionTestingModule",
    "InjectionPayload",
    "CVESuiteModule",
    "CVECheck",
    "SlingSmuggler",
    "JCRInferenceEngine",
    "ServiceProbeModule",
]
