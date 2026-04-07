"""Attack Graph Reporting System for AEM Offensive Framework.

Generates visual attack graphs showing vulnerability chains from initial access to full compromise.
"""

import json
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import networkx as nx

from core.models import Finding, VulnSeverity, AttackPath, ScanResult, ScanPhase


@dataclass
class AttackNode:
    """Represents a node in the attack graph."""
    id: str
    name: str
    description: str
    finding: Optional[Finding] = None
    severity: VulnSeverity = VulnSeverity.INFO
    prerequisites: List[str] = field(default_factory=list)
    leads_to: List[str] = field(default_factory=list)


@dataclass
class AttackEdge:
    """Represents an edge in the attack graph."""
    source: str
    target: str
    technique: str
    confidence: float = 1.0


class AttackGraph:
    """Represents and generates attack graphs."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self.entry_points: Set[str] = set()
        self.critical_nodes: Set[str] = set()
    
    def add_finding(self, finding: Finding):
        """Add a finding as a node in the attack graph."""
        node_id = finding.id
        
        node = AttackNode(
            id=node_id,
            name=finding.title,
            description=finding.description,
            finding=finding,
            severity=finding.severity,
            prerequisites=finding.prerequisites
        )
        
        self.nodes[node_id] = node
        self.graph.add_node(
            node_id,
            name=node.name,
            severity=finding.severity.value,
            phase=finding.phase.value,
            technique=finding.technique
        )
        
        # Mark as entry point if it's fingerprinting or low severity discovery
        if finding.phase == ScanPhase.FINGERPRINTING or (
            finding.phase == ScanPhase.DISCOVERY and finding.severity in [VulnSeverity.INFO, VulnSeverity.LOW]
        ):
            self.entry_points.add(node_id)
    
    def add_edge(self, source_id: str, target_id: str, technique: str, confidence: float = 1.0):
        """Add an edge between two findings."""
        if source_id in self.nodes and target_id in self.nodes:
            edge = AttackEdge(source_id, target_id, technique, confidence)
            self.edges.append(edge)
            self.graph.add_edge(
                source_id, 
                target_id,
                technique=technique,
                confidence=confidence
            )
            
            # Update node connections
            self.nodes[source_id].leads_to.append(target_id)
    
    def build_chains(self):
        """Build attack chains from entry points to critical vulnerabilities."""
        chains = []
        
        # Find all paths from entry points to high/critical findings
        for entry in self.entry_points:
            for target_id, node in self.nodes.items():
                if node.severity in [VulnSeverity.HIGH, VulnSeverity.CRITICAL]:
                    try:
                        paths = list(nx.all_simple_paths(
                            self.graph, entry, target_id, cutoff=5
                        ))
                        for path in paths:
                            chains.append(self._path_to_chain(path))
                    except nx.NetworkXNoPath:
                        continue
        
        return chains
    
    def _path_to_chain(self, path: List[str]) -> AttackPath:
        """Convert a graph path to an AttackPath."""
        findings = [self.nodes[node_id].finding for node_id in path]
        findings = [f for f in findings if f is not None]
        
        if not findings:
            return None
        
        entry_finding = findings[0]
        final_finding = findings[-1]
        
        return AttackPath(
            id=f"CHAIN-{path[0]}-{path[-1]}",
            name=f"{entry_finding.title} → {final_finding.title}",
            description=f"Attack chain from {entry_finding.technique} to {final_finding.technique}",
            findings=findings,
            entry_point=entry_finding.url,
            impact=final_finding.title,
            complexity=self._calculate_complexity(path)
        )
    
    def _calculate_complexity(self, path: List[str]) -> str:
        """Calculate attack complexity based on path length and required techniques."""
        length = len(path)
        
        if length <= 2:
            return "Low"
        elif length <= 4:
            return "Medium"
        else:
            return "High"
    
    def identify_critical_paths(self) -> List[AttackPath]:
        """Identify the most critical attack paths."""
        chains = self.build_chains()
        
        # Score chains by severity and length
        scored_chains = []
        for chain in chains:
            if chain is None:
                continue
                
            severity_score = sum(
                4 if f.severity == VulnSeverity.CRITICAL else
                3 if f.severity == VulnSeverity.HIGH else
                2 if f.severity == VulnSeverity.MEDIUM else 1
                for f in chain.findings
            )
            
            # Prefer shorter chains with high impact
            efficiency = severity_score / len(chain.findings)
            scored_chains.append((efficiency, chain))
        
        # Sort by efficiency score
        scored_chains.sort(key=lambda x: x[0], reverse=True)
        
        # Return top chains
        return [chain for _, chain in scored_chains[:10]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert attack graph to dictionary representation."""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "name": node.name,
                    "severity": node.severity.value,
                    "phase": node.finding.phase.value if node.finding else None,
                    "technique": node.finding.technique if node.finding else None,
                    "url": node.finding.url if node.finding else None,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "technique": edge.technique,
                    "confidence": edge.confidence
                }
                for edge in self.edges
            ],
            "entry_points": list(self.entry_points),
            "critical_paths": [
                {
                    "id": path.id,
                    "name": path.name,
                    "entry_point": path.entry_point,
                    "impact": path.impact,
                    "complexity": path.complexity,
                    "findings_count": len(path.findings),
                    "findings": [f.id for f in path.findings]
                }
                for path in self.identify_critical_paths()
            ],
            "statistics": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "entry_points": len(self.entry_points),
                "critical_nodes": len(self.critical_nodes)
            }
        }
    
    def to_dot(self) -> str:
        """Generate DOT format for graph visualization."""
        lines = ["digraph AttackGraph {"]
        lines.append('    rankdir=LR;')
        lines.append('    node [shape=box];')
        
        # Add nodes with colors based on severity
        severity_colors = {
            VulnSeverity.CRITICAL: "red",
            VulnSeverity.HIGH: "orange",
            VulnSeverity.MEDIUM: "yellow",
            VulnSeverity.LOW: "lightblue",
            VulnSeverity.INFO: "lightgray"
        }
        
        for node_id, node in self.nodes.items():
            color = severity_colors.get(node.severity, "white")
            label = node.name[:30] + "..." if len(node.name) > 30 else node.name
            lines.append(f'    "{node_id}" [label="{label}", fillcolor={color}, style=filled];')
        
        # Add edges
        for edge in self.edges:
            lines.append(f'    "{edge.source}" -> "{edge.target}" [label="{edge.technique}"];')
        
        lines.append("}")
        return "\n".join(lines)


class ReportGenerator:
    """Generates comprehensive scan reports."""
    
    def __init__(self, scan_result: ScanResult):
        self.scan_result = scan_result
        self.attack_graph = AttackGraph()
        self._build_graph()
    
    def _build_graph(self):
        """Build attack graph from scan findings."""
        # Add all findings as nodes
        for finding in self.scan_result.findings:
            self.attack_graph.add_finding(finding)
        
        # Create edges based on chainability and prerequisites
        for finding in self.scan_result.findings:
            if finding.chainable:
                # Connect to other findings with matching prerequisites
                for other in self.scan_result.findings:
                    if other.id != finding.id:
                        # Check if this finding enables the other
                        if self._is_related(finding, other):
                            self.attack_graph.add_edge(
                                finding.id,
                                other.id,
                                f"{finding.technique} → {other.technique}",
                                confidence=0.8
                            )
    
    def _is_related(self, finding1: Finding, finding2: Finding) -> bool:
        """Check if two findings are related in an attack chain."""
        # Same URL path
        if finding1.url == finding2.url:
            return True
        
        # One finding's technique enables another
        enabling_patterns = {
            "Fingerprinting": ["Discovery", "Exploitation"],
            "Discovery": ["Exploitation"],
            "Bypass": ["Exploitation"],
            "Dispatcher": ["OSGi", "JCR"],
        }
        
        for pattern, enabled in enabling_patterns.items():
            if pattern in finding1.technique:
                if any(e in finding2.technique for e in enabled):
                    return True
        
        return False
    
    def generate_json_report(self) -> str:
        """Generate JSON report."""
        report = {
            "scan_metadata": {
                "target": self.scan_result.target,
                "start_time": self.scan_result.start_time.isoformat() if self.scan_result.start_time else None,
                "end_time": self.scan_result.end_time.isoformat() if self.scan_result.end_time else None,
                "total_findings": len(self.scan_result.findings),
            },
            "findings": [
                {
                    "id": f.id,
                    "phase": f.phase.value,
                    "technique": f.technique,
                    "url": f.url,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "bypass_used": f.bypass_used.value if f.bypass_used else None,
                    "chainable": f.chainable,
                    "timestamp": f.timestamp.isoformat()
                }
                for f in self.scan_result.findings
            ],
            "attack_graph": self.attack_graph.to_dict(),
            "statistics": self._calculate_statistics(),
            "executive_summary": self._generate_executive_summary()
        }
        
        return json.dumps(report, indent=2)
    
    def generate_html_report(self) -> str:
        """Generate HTML report."""
        severity_counts = self._calculate_statistics()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>AEM Offensive Security Report - {self.scan_result.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #17a2b8; }}
        .info {{ border-left: 5px solid #6c757d; }}
        .attack-path {{ background: #e9ecef; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>AEM Offensive Security Assessment Report</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Target:</strong> {self.scan_result.target}</p>
        <p><strong>Scan Date:</strong> {self.scan_result.start_time}</p>
        <p><strong>Total Findings:</strong> {len(self.scan_result.findings)}</p>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>Critical</td><td>{severity_counts.get('critical', 0)}</td></tr>
            <tr><td>High</td><td>{severity_counts.get('high', 0)}</td></tr>
            <tr><td>Medium</td><td>{severity_counts.get('medium', 0)}</td></tr>
            <tr><td>Low</td><td>{severity_counts.get('low', 0)}</td></tr>
            <tr><td>Info</td><td>{severity_counts.get('info', 0)}</td></tr>
        </table>
    </div>
    
    <h2>Attack Paths</h2>
    {self._generate_attack_paths_html()}
    
    <h2>Findings Details</h2>
    {self._generate_findings_html()}
</body>
</html>"""
        return html
    
    def _generate_attack_paths_html(self) -> str:
        """Generate HTML for attack paths section."""
        paths = self.attack_graph.identify_critical_paths()
        
        if not paths:
            return "<p>No significant attack paths identified.</p>"
        
        html_parts = []
        for path in paths:
            steps = " → ".join([f.title for f in path.findings])
            html_parts.append(f"""
    <div class="attack-path">
        <h3>{path.name}</h3>
        <p><strong>Complexity:</strong> {path.complexity}</p>
        <p><strong>Entry Point:</strong> {path.entry_point}</p>
        <p><strong>Impact:</strong> {path.impact}</p>
        <p><strong>Chain:</strong> {steps}</p>
    </div>
""")
        return "\n".join(html_parts)
    
    def _generate_findings_html(self) -> str:
        """Generate HTML for findings section."""
        severity_class = {
            VulnSeverity.CRITICAL: "critical",
            VulnSeverity.HIGH: "high",
            VulnSeverity.MEDIUM: "medium",
            VulnSeverity.LOW: "low",
            VulnSeverity.INFO: "info"
        }
        
        html_parts = []
        for finding in sorted(
            self.scan_result.findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 5)
        ):
            css_class = severity_class.get(finding.severity, "info")
            html_parts.append(f"""
    <div class="finding {css_class}">
        <h3>[{finding.severity.value.upper()}] {finding.title}</h3>
        <p><strong>URL:</strong> {finding.url}</p>
        <p><strong>Technique:</strong> {finding.technique}</p>
        <p><strong>Phase:</strong> {finding.phase.value}</p>
        <p>{finding.description}</p>
        {f'<p><strong>Bypass:</strong> {finding.bypass_used.value}</p>' if finding.bypass_used else ''}
    </div>
""")
        return "\n".join(html_parts)
    
    def _calculate_statistics(self) -> Dict[str, int]:
        """Calculate statistics for the report."""
        stats = defaultdict(int)
        
        for finding in self.scan_result.findings:
            stats[finding.severity.value] += 1
            stats[f"phase_{finding.phase.value}"] += 1
        
        stats["total"] = len(self.scan_result.findings)
        stats["chainable"] = sum(1 for f in self.scan_result.findings if f.chainable)
        
        return dict(stats)
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        stats = self._calculate_statistics()
        critical_paths = self.attack_graph.identify_critical_paths()
        
        summary = f"""
AEM Offensive Security Assessment Summary for {self.scan_result.target}

CRITICAL FINDINGS: {stats.get('critical', 0)}
HIGH FINDINGS: {stats.get('high', 0)}
MEDIUM FINDINGS: {stats.get('medium', 0)}
LOW FINDINGS: {stats.get('low', 0)}

ATTACK PATHS IDENTIFIED: {len(critical_paths)}

KEY FINDINGS:
"""
        
        # Add top 5 most critical findings
        critical_findings = [
            f for f in self.scan_result.findings 
            if f.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]
        ]
        
        for finding in critical_findings[:5]:
            summary += f"\n- [{finding.severity.value.upper()}] {finding.title}: {finding.url}"
        
        if critical_paths:
            summary += "\n\nCRITICAL ATTACK CHAINS:\n"
            for path in critical_paths[:3]:
                summary += f"\n1. {path.name}\n"
                summary += f"   Entry: {path.entry_point}\n"
                summary += f"   Impact: {path.impact}\n"
                summary += f"   Complexity: {path.complexity}\n"
        
        return summary
    
    def save_reports(self, base_path: str):
        """Save all report formats."""
        import os
        
        # JSON report
        json_path = f"{base_path}.json"
        with open(json_path, 'w') as f:
            f.write(self.generate_json_report())
        
        # HTML report
        html_path = f"{base_path}.html"
        with open(html_path, 'w') as f:
            f.write(self.generate_html_report())
        
        # DOT file for graph visualization
        dot_path = f"{base_path}.dot"
        with open(dot_path, 'w') as f:
            f.write(self.attack_graph.to_dot())
        
        return {
            "json": json_path,
            "html": html_path,
            "dot": dot_path
        }
