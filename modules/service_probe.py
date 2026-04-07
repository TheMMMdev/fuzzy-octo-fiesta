"""Service-Specific Deep Probing Module.

Targets AEM internal services for information leakage:
- Replication & Flush agents (credentials, transport URIs)
- SiteCatalyst / Analytics cloud service configurations
- Audit logs and system statistics
- Package Manager enumeration
- System console status archives
"""

import json
import re
from typing import List, Dict, Optional

from core.models import Finding, VulnSeverity, ScanPhase
from core.config import AEMConfig
from core.engine import HTTPXEngine
from bypass.transformers import BypassTransformer


class ServiceProbeModule:
    """Deep probing for AEM-specific internal services."""
    
    # Replication agent endpoints
    REPLICATION_ENDPOINTS: List[Dict[str, str]] = [
        {"path": "/etc/replication/agents.author.json", "desc": "Author replication agents"},
        {"path": "/etc/replication/agents.publish.json", "desc": "Publish replication agents"},
        {"path": "/etc/replication/agents.author.1.json", "desc": "Author agents (depth 1)"},
        {"path": "/etc/replication/agents.publish.1.json", "desc": "Publish agents (depth 1)"},
        {"path": "/etc/replication/agents.author.infinity.json", "desc": "Author agents (full dump)"},
        {"path": "/etc/replication.infinity.json", "desc": "All replication config"},
        {"path": "/etc/replication/treeactivation.html", "desc": "Tree activation UI"},
        {"path": "/bin/replicate.json", "desc": "Replicate servlet"},
        {"path": "/bin/receive", "desc": "Replication receiver"},
        {"path": "/etc/replication-agents.1.json", "desc": "Replication agents alt path"},
        {"path": "/etc/reverse-replication-agents.1.json", "desc": "Reverse replication agents"},
        {"path": "/etc/flush-agents.1.json", "desc": "Flush agents config"},
        {"path": "/etc/static-replication-agents.1.json", "desc": "Static replication agents"},
        {"path": "/dispatcher/invalidate.cache", "desc": "Dispatcher cache invalidation"},
    ]
    
    # Analytics / SiteCatalyst cloud service endpoints
    ANALYTICS_ENDPOINTS: List[Dict[str, str]] = [
        {"path": "/etc/cloudservices/sitecatalyst.json", "desc": "SiteCatalyst config"},
        {"path": "/etc/cloudservices/sitecatalyst.1.json", "desc": "SiteCatalyst config (depth 1)"},
        {"path": "/etc/cloudservices/sitecatalyst.infinity.json", "desc": "SiteCatalyst full dump"},
        {"path": "/etc/cloudservices/analytics.json", "desc": "Analytics config"},
        {"path": "/etc/cloudservices/analytics.1.json", "desc": "Analytics config (depth 1)"},
        {"path": "/etc/cloudservices/analytics.infinity.json", "desc": "Analytics full dump"},
        {"path": "/etc/cloudservices.1.json", "desc": "All cloud services"},
        {"path": "/etc/cloudservices.infinity.json", "desc": "All cloud services (full dump)"},
        {"path": "/etc/cloudservices/dynamictagmanagement.json", "desc": "DTM config"},
        {"path": "/etc/cloudservices/googleanalytics.json", "desc": "Google Analytics config"},
        {"path": "/etc/cloudservices/s7.json", "desc": "Scene7 config"},
        {"path": "/etc/cloudservices/scene7.json", "desc": "Scene7 alt config"},
        {"path": "/etc/cloudservices/facebook.json", "desc": "Facebook config"},
        {"path": "/etc/cloudservices/twitter.json", "desc": "Twitter config"},
        {"path": "/etc/cloudservices/salesforce.json", "desc": "Salesforce config"},
        {"path": "/etc/cloudservices/exacttarget.json", "desc": "ExactTarget config"},
        {"path": "/etc/cloudservices/mailchimp.json", "desc": "Mailchimp config"},
        {"path": "/etc/cloudservices/silverpop.json", "desc": "Silverpop config"},
        {"path": "/etc/cloudservices/campaign.json", "desc": "Campaign config"},
        {"path": "/etc/cloudservices/recaptcha.json", "desc": "reCaptcha config"},
        {"path": "/etc/cloudservices/translation.json", "desc": "Translation config"},
        {"path": "/etc/cloudservices/msft-translation.json", "desc": "MS Translation config"},
    ]
    
    # Audit log and statistics endpoints
    AUDIT_ENDPOINTS: List[Dict[str, str]] = [
        {"path": "/var/audit.json", "desc": "Audit logs root"},
        {"path": "/var/audit.1.json", "desc": "Audit logs (depth 1)"},
        {"path": "/var/audit.2.json", "desc": "Audit logs (depth 2)"},
        {"path": "/var/audit/com.day.cq.wcm.core.page.json", "desc": "Page audit log"},
        {"path": "/var/audit/com.day.cq.wcm.core.page.1.json", "desc": "Page audit (depth 1)"},
        {"path": "/var/audit/com.day.cq.replication.json", "desc": "Replication audit log"},
        {"path": "/var/audit/com.day.cq.replication.1.json", "desc": "Replication audit (depth 1)"},
        {"path": "/var/audit/com.day.cq.security.json", "desc": "Security audit log"},
        {"path": "/var/statistics.json", "desc": "Statistics root"},
        {"path": "/var/statistics.1.json", "desc": "Statistics (depth 1)"},
        {"path": "/var/statistics/pages.json", "desc": "Page statistics"},
        {"path": "/var/eventing.json", "desc": "Eventing data"},
        {"path": "/var/eventing.1.json", "desc": "Eventing (depth 1)"},
        {"path": "/var/discovery.json", "desc": "Topology discovery"},
        {"path": "/var/discovery.1.json", "desc": "Topology discovery (depth 1)"},
        {"path": "/var/replication.json", "desc": "Replication queue"},
        {"path": "/var/replication.1.json", "desc": "Replication queue (depth 1)"},
    ]
    
    # System console status / archive endpoints
    SYSTEM_CONSOLE_ENDPOINTS: List[Dict[str, str]] = [
        {"path": "/system/console/status-productinfo.json", "desc": "Product info"},
        {"path": "/system/console/status-Bundlelist.txt", "desc": "Bundle list"},
        {"path": "/system/console/status-productinfo.tar.gz", "desc": "Product info archive"},
        {"path": "/system/console/status-System Properties.txt", "desc": "System properties"},
        {"path": "/system/console/status-osgi-installer.txt", "desc": "OSGi installer status"},
        {"path": "/system/console/status-jcr-observation.txt", "desc": "JCR observation status"},
        {"path": "/system/console/status-Configurations.txt", "desc": "All configurations"},
        {"path": "/system/console/status-oak-index-stats.txt", "desc": "Oak index statistics"},
        {"path": "/system/console/status-Dumped Threads.txt", "desc": "Thread dump"},
        {"path": "/system/console/jmx", "desc": "JMX console"},
        {"path": "/system/console/jmx/java.lang%3Atype%3DRuntime.json", "desc": "JMX Runtime info"},
        {"path": "/system/console/jmx/java.lang%3Atype%3DMemory.json", "desc": "JMX Memory info"},
        {"path": "/system/console/requests.json", "desc": "Recent requests"},
    ]
    
    # Package Manager endpoints
    PACKAGE_ENDPOINTS: List[Dict[str, str]] = [
        {"path": "/crx/packmgr/list.jsp", "desc": "Package list"},
        {"path": "/crx/packmgr/groups.jsp", "desc": "Package groups"},
        {"path": "/crx/packmgr/installstatus.jsp", "desc": "Install status"},
        {"path": "/crx/packmgr/service.jsp?cmd=ls", "desc": "Package service list"},
        {"path": "/crx/packmgr/index.jsp", "desc": "Package Manager UI"},
        {"path": "/etc/packages.json", "desc": "Packages JSON"},
        {"path": "/etc/packages.1.json", "desc": "Packages JSON (depth 1)"},
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer):
        self.engine = engine
        self.config = config
        self.bypass = bypass
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run all service-specific probes."""
        findings: List[Finding] = []
        
        # Replication & Flush agents
        rep_findings = await self._probe_replication(base_url)
        findings.extend(rep_findings)
        
        # Analytics / SiteCatalyst
        analytics_findings = await self._probe_analytics(base_url)
        findings.extend(analytics_findings)
        
        # Audit logs & statistics
        audit_findings = await self._probe_audits(base_url)
        findings.extend(audit_findings)
        
        # System console status
        console_findings = await self._probe_system_console(base_url)
        findings.extend(console_findings)
        
        # Package Manager
        pkg_findings = await self._probe_packages(base_url)
        findings.extend(pkg_findings)
        
        return findings
    
    async def _probe_replication(self, base_url: str) -> List[Finding]:
        """Probe replication and flush agent configurations."""
        findings = []
        
        for endpoint in self.REPLICATION_ENDPOINTS:
            path = endpoint["path"]
            url = f"{base_url}{path}"
            
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, path,
                bypass_transformer=self.bypass,
                max_bypass_attempts=15
            )
            
            if response.status_code == 200 and len(response.text) > 20:
                severity = VulnSeverity.MEDIUM
                cred_leak = False
                
                # Check for credential leakage in replication config
                text_lower = response.text.lower()
                cred_indicators = [
                    "transportpassword", "transportuser", "transporturi",
                    "password", "secret", "credentials", "agent.userid",
                ]
                if any(ci in text_lower for ci in cred_indicators):
                    severity = VulnSeverity.CRITICAL
                    cred_leak = True
                elif "enabled" in text_lower or "jcr:primaryType" in response.text:
                    severity = VulnSeverity.HIGH
                
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique="Service Probe: Replication",
                    url=response.url or url,
                    severity=severity,
                    title=f"Replication Config Exposed: {endpoint['desc']}",
                    description=(
                        f"Replication agent configuration at {path} is accessible"
                        f"{' — CREDENTIAL LEAKAGE DETECTED' if cred_leak else ''}"
                    ),
                    evidence={
                        "endpoint": path,
                        "description": endpoint["desc"],
                        "response_size": len(response.text),
                        "credential_leak": cred_leak,
                        "sample": response.text[:500],
                        "bypass_used": response.bypass_used,
                    },
                    chainable=True
                ))
        
        return findings
    
    async def _probe_analytics(self, base_url: str) -> List[Finding]:
        """Probe SiteCatalyst and analytics cloud service configs."""
        findings = []
        
        for endpoint in self.ANALYTICS_ENDPOINTS:
            path = endpoint["path"]
            url = f"{base_url}{path}"
            
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, path,
                bypass_transformer=self.bypass,
                max_bypass_attempts=10
            )
            
            if response.status_code == 200 and len(response.text) > 20:
                severity = VulnSeverity.MEDIUM
                
                # Check for API keys / credentials
                text_lower = response.text.lower()
                api_indicators = [
                    "apikey", "api_key", "api-key", "secret",
                    "client_secret", "clientsecret", "token",
                    "rsid", "trackingserver", "s_account",
                    "oauth", "password",
                ]
                has_api_keys = any(ai in text_lower for ai in api_indicators)
                
                if has_api_keys:
                    severity = VulnSeverity.CRITICAL
                elif "jcr:primaryType" in response.text:
                    severity = VulnSeverity.HIGH
                
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique="Service Probe: Analytics",
                    url=response.url or url,
                    severity=severity,
                    title=f"Cloud Service Exposed: {endpoint['desc']}",
                    description=(
                        f"Cloud service configuration at {path} is accessible"
                        f"{' — API CREDENTIALS DETECTED' if has_api_keys else ''}"
                    ),
                    evidence={
                        "endpoint": path,
                        "description": endpoint["desc"],
                        "response_size": len(response.text),
                        "api_keys_found": has_api_keys,
                        "sample": response.text[:500],
                        "bypass_used": response.bypass_used,
                    },
                    chainable=True
                ))
        
        return findings
    
    async def _probe_audits(self, base_url: str) -> List[Finding]:
        """Probe audit logs and statistics endpoints."""
        findings = []
        
        for endpoint in self.AUDIT_ENDPOINTS:
            path = endpoint["path"]
            url = f"{base_url}{path}"
            
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, path,
                bypass_transformer=self.bypass,
                max_bypass_attempts=10
            )
            
            if response.status_code == 200 and len(response.text) > 20:
                severity = VulnSeverity.MEDIUM
                
                # Higher severity for security audits or data with user info
                if "security" in path or "user" in response.text.lower():
                    severity = VulnSeverity.HIGH
                
                findings.append(Finding(
                    phase=ScanPhase.DISCOVERY,
                    technique="Service Probe: Audit Logs",
                    url=response.url or url,
                    severity=severity,
                    title=f"Audit Data Exposed: {endpoint['desc']}",
                    description=f"Audit/statistics data at {path} is accessible",
                    evidence={
                        "endpoint": path,
                        "description": endpoint["desc"],
                        "response_size": len(response.text),
                        "sample": response.text[:500],
                        "bypass_used": response.bypass_used,
                    },
                    chainable=True
                ))
        
        return findings
    
    async def _probe_system_console(self, base_url: str) -> List[Finding]:
        """Probe system console status and archive endpoints."""
        findings = []
        
        for endpoint in self.SYSTEM_CONSOLE_ENDPOINTS:
            path = endpoint["path"]
            url = f"{base_url}{path}"
            
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, path,
                bypass_transformer=self.bypass,
                max_bypass_attempts=15
            )
            
            if response.status_code == 200 and len(response.text) > 50:
                severity = VulnSeverity.HIGH
                
                # System properties or thread dumps are critical
                if "properties" in path.lower() or "thread" in path.lower():
                    severity = VulnSeverity.CRITICAL
                
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique="Service Probe: System Console",
                    url=response.url or url,
                    severity=severity,
                    title=f"System Console Status: {endpoint['desc']}",
                    description=f"System console status endpoint at {path} is accessible",
                    evidence={
                        "endpoint": path,
                        "description": endpoint["desc"],
                        "response_size": len(response.text),
                        "sample": response.text[:500],
                        "bypass_used": response.bypass_used,
                    },
                    chainable=True
                ))
        
        return findings
    
    async def _probe_packages(self, base_url: str) -> List[Finding]:
        """Probe Package Manager for installed packages."""
        findings = []
        
        for endpoint in self.PACKAGE_ENDPOINTS:
            path = endpoint["path"]
            url = f"{base_url}{path}"
            
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, path,
                bypass_transformer=self.bypass,
                max_bypass_attempts=15
            )
            
            if response.status_code == 200 and len(response.text) > 50:
                # Try to count packages
                pkg_count = 0
                try:
                    data = json.loads(response.text)
                    if isinstance(data, dict):
                        pkg_count = len(data.get("results", []))
                    elif isinstance(data, list):
                        pkg_count = len(data)
                except (json.JSONDecodeError, KeyError):
                    pkg_count = response.text.count(".zip")
                
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique="Service Probe: Package Manager",
                    url=response.url or url,
                    severity=VulnSeverity.HIGH,
                    title=f"Package Manager Accessible: {endpoint['desc']}",
                    description=(
                        f"Package Manager at {path} is accessible"
                        f" ({pkg_count} packages found)" if pkg_count else
                        f"Package Manager at {path} is accessible"
                    ),
                    evidence={
                        "endpoint": path,
                        "description": endpoint["desc"],
                        "package_count": pkg_count,
                        "response_size": len(response.text),
                        "sample": response.text[:500],
                        "bypass_used": response.bypass_used,
                    },
                    chainable=True
                ))
        
        return findings
