"""JCR & Sling Resource Probing module for AEM Offensive Framework."""

import json
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from core.models import Finding, VulnSeverity, ScanPhase
from core.config import AEMConfig
from core.engine import HTTPXEngine
from core.phases import PhaseResult


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
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig):
        self.engine = engine
        self.config = config
        self.nodes_cache: Dict[str, JCRNode] = {}
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run full JCR probing suite."""
        findings = []
        
        # Test dangerous selectors
        selector_findings = await self._test_selectors(base_url)
        findings.extend(selector_findings)
        
        # Probe critical paths
        for path in self.CRITICAL_PATHS:
            path_findings = await self._probe_path(base_url, path)
            findings.extend(path_findings)
        
        # Check for sensitive data exposure
        sensitive_findings = await self._check_sensitive_exposure(base_url)
        findings.extend(sensitive_findings)
        
        # QueryBuilder probe
        qb_findings = await self._probe_querybuilder(base_url)
        findings.extend(qb_findings)
        
        return findings
    
    async def _test_selectors(self, base_url: str) -> List[Finding]:
        """Test dangerous selectors on various paths."""
        findings = []
        test_paths = ["/content", "/etc", "/var", "/libs"]
        
        for path in test_paths:
            for selector in self.DANGEROUS_SELECTORS:
                url = f"{base_url}{path}{selector}"
                response = await self.engine.get(url)
                
                if response.status_code == 200:
                    try:
                        data = json.loads(response.text)
                        
                        # Calculate severity based on selector type
                        severity = VulnSeverity.MEDIUM
                        if "infinity" in selector:
                            severity = VulnSeverity.CRITICAL
                        elif selector in [".1.json", ".2.json"]:
                            severity = VulnSeverity.HIGH
                        
                        # Analyze content
                        node_count = self._count_nodes(data)
                        sensitive_props = self._find_sensitive_props(data)
                        
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
            
            if response.status_code == 200:
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
            
            if response.status_code == 200:
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
    
    async def _probe_querybuilder(self, base_url: str) -> List[Finding]:
        """Probe QueryBuilder for information leakage."""
        findings = []
        qb_endpoint = f"{base_url}/bin/querybuilder.json"
        
        # Test basic querybuilder access
        basic_test = await self.engine.get(qb_endpoint)
        
        if basic_test.status_code == 200:
            findings.append(Finding(
                phase=ScanPhase.DISCOVERY,
                technique="QueryBuilder Exposure",
                url=qb_endpoint,
                severity=VulnSeverity.HIGH,
                title="QueryBuilder Endpoint Accessible",
                description="/bin/querybuilder.json is accessible without authentication",
                evidence={"status": basic_test.status_code}
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
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    hits = data.get("hits", [])
                    
                    if len(hits) > 0:
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="QueryBuilder Data Leak",
                            url=url,
                            severity=VulnSeverity.HIGH,
                            title=f"QueryBuilder Leaks {desc}",
                            description=f"QueryBuilder query returned {len(hits)} results for {desc}",
                            evidence={
                                "query": query_url,
                                "result_count": len(hits),
                                "sample_results": hits[:5]
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
