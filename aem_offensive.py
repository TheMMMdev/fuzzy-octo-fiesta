#!/usr/bin/env python3
"""Slingblade - AEM Offensive Security Framework

A sharp tool for penetrating Adobe Experience Manager defenses.
Multi-phase discovery, bypass techniques, and deep service probing.
"""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.panel import Panel

from core.config import AEMConfig
from core.engine import HTTPXEngine
from core.models import ScanResult, TargetInfo
from core.phases import PhaseManager
from bypass.transformers import BypassTransformer

# Import modules
from modules.jcr_probe import JCRProbingModule
from modules.osgi_exploit import OSGiExploitationModule
from modules.injection import InjectionTestingModule
from modules.cve_suite import CVESuiteModule
from modules.sling_smuggler import SlingSmuggler
from modules.jcr_inference import JCRInferenceEngine
from modules.service_probe import ServiceProbeModule

# Import reporting
from reporting.attack_graph import ReportGenerator

# Version info
__version__ = "1.0.0"
__author__ = "Slingblade Security Framework"

app = typer.Typer(
    name="slingblade",
    help="Slingblade — AEM Offensive Security Framework",
    add_completion=False
)

console = Console()


def print_banner():
    """Print the Slingblade banner."""
    console.print("")
    console.print("[bold red]    ╔═══════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]    ║[/bold red]                                                           [bold red]║[/bold red]")
    console.print("[bold red]    ║[/bold red]              [bold white]SLINGBLADE[/bold white]                                  [bold red]║[/bold red]")
    console.print("[bold red]    ║[/bold red]                                                           [bold red]║[/bold red]")
    console.print("[bold red]    ╚═══════════════════════════════════════════════════════════╝[/bold red]")
    console.print(f"[bold yellow]         AEM Offensive Security Framework v{__version__}[/bold yellow]")
    console.print("[dim]         Apache Sling / OSGi / JCR Exploitation Toolkit[/dim]")
    console.print("")


# Severity color/symbol map for live output
_SEV_STYLE = {
    "critical": ("[bold red]CRIT[/bold red]", "!!"),
    "high":     ("[orange1]HIGH[/orange1]", "!"),
    "medium":   ("[yellow]MED [/yellow]", "*"),
    "low":      ("[cyan]LOW [/cyan]", "-"),
    "info":     ("[dim]INFO[/dim]", "."),
}


def validate_url(url: str) -> str:
    """Validate and normalize URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


def load_targets(url: Optional[str] = None, targets_file: Optional[str] = None) -> List[str]:
    """Load and validate target URLs from argument and/or file.
    
    Supports:
    - Single URL:  python aem_offensive.py scan https://example.com
    - Comma-sep:   python aem_offensive.py scan https://a.com,https://b.com
    - File (-L):   python aem_offensive.py scan -L hosts.txt
    - Both:        python aem_offensive.py scan https://c.com -L hosts.txt
    """
    targets: List[str] = []
    
    if url:
        for u in url.split(","):
            u = u.strip()
            if u:
                targets.append(validate_url(u))
    
    if targets_file:
        p = Path(targets_file)
        if not p.exists():
            console.print(f"[bold red]Error:[/bold red] targets file not found: {targets_file}")
            sys.exit(1)
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(validate_url(line))
    
    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    
    return unique


def _print_finding_live(finding, target: str = ""):
    """Print a single finding to the console as it arrives (sprintf-style)."""
    sev = finding.severity.value
    label, _ = _SEV_STYLE.get(sev, ("[dim]????[/dim]", "?"))
    bypass_tag = ""
    if finding.bypass_used:
        bypass_tag = f" [dim](bypass: {finding.bypass_used.value})[/dim]"
    host_tag = ""
    if target:
        host_tag = f"[dim]{target}[/dim] "
    console.print(f"  {label} {host_tag}{finding.title} — [underline]{finding.url}[/underline]{bypass_tag}")


def _collect_and_emit(result: ScanResult, new_findings, on_finding=None, target: str = ""):
    """Add findings to result and emit each one via callback."""
    for f in new_findings:
        result.findings.append(f)
        if on_finding:
            on_finding(f, target)


async def run_scan(
    target_url: str,
    config: AEMConfig,
    on_finding: Optional[Callable] = None,
) -> ScanResult:
    """Execute the full scan workflow with optional live finding callback.
    
    Args:
        target_url: The target URL to scan.
        config: Scan configuration.
        on_finding: Optional callback(finding, target) invoked per finding.
    """
    start_time = datetime.utcnow()
    
    result = ScanResult(
        target=target_url,
        start_time=start_time,
        target_info=TargetInfo(url=target_url)
    )
    
    bypass = BypassTransformer()
    
    async with HTTPXEngine(config) as engine:
        await engine.calibrate_soft_404(target_url)
        
        phase_manager = PhaseManager(engine, config)
        
        # Phase 1-3: Multi-phase discovery
        console.print(f"[cyan]  ▸ Multi-phase discovery...[/cyan]")
        phase_results = await phase_manager.run_all_phases(target_url)
        for phase_result in phase_results:
            _collect_and_emit(result, phase_result.findings, on_finding, target_url)
            if phase_result.target_info:
                result.target_info = phase_result.target_info
            if engine.should_abort:
                console.print("[yellow]  ⚠ Scan aborted — excessive failures[/yellow]")
                break
        
        # Module pipeline — (label, enabled flag, factory)
        modules = [
            ("JCR Probing",          config.enable_jcr_probe,       lambda: JCRProbingModule(engine, config, bypass)),
            ("OSGi Exploitation",    config.enable_osgi_exploit,    lambda: OSGiExploitationModule(engine, config, bypass)),
            ("Injection Testing",    config.enable_injection,       lambda: InjectionTestingModule(engine, config)),
            ("CVE Suite",            config.enable_cve_suite,       lambda: CVESuiteModule(engine, config, bypass)),
            ("Sling Smuggler",       config.enable_sling_smuggler,  lambda: SlingSmuggler(engine, config, bypass)),
            ("JCR Inference",        config.enable_jcr_inference,   lambda: JCRInferenceEngine(engine, config, bypass)),
            ("Service Probe",        config.enable_service_probe,   lambda: ServiceProbeModule(engine, config, bypass)),
        ]
        
        for label, enabled, factory in modules:
            if not enabled or engine.should_abort:
                continue
            console.print(f"[cyan]  ▸ {label}...[/cyan]")
            module_instance = factory()
            module_findings = await module_instance.run(target_url)
            _collect_and_emit(result, module_findings, on_finding, target_url)
            if engine.should_abort:
                console.print("[yellow]  ⚠ Scan aborted — excessive failures[/yellow]")
    
    result.end_time = datetime.utcnow()
    result.statistics = {
        "total_findings": len(result.findings),
        "critical": sum(1 for f in result.findings if f.severity.value == "critical"),
        "high": sum(1 for f in result.findings if f.severity.value == "high"),
        "medium": sum(1 for f in result.findings if f.severity.value == "medium"),
        "low": sum(1 for f in result.findings if f.severity.value == "low"),
        "info": sum(1 for f in result.findings if f.severity.value == "info"),
        "http_requests": engine.stats.get("total_requests", 0),
        "cache_hits": engine._cache_hits,
    }
    
    return result


def print_results(result: ScanResult):
    """Print scan results to console."""
    
    # Summary table
    table = Table(title="Scan Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")
    
    table.add_row("Target", result.target)
    table.add_row("Server Type", result.target_info.server_type.value if result.target_info else "unknown")
    table.add_row("Total Findings", str(result.statistics.get("total_findings", 0)))
    table.add_row("Critical", str(result.statistics.get("critical", 0)))
    table.add_row("High", str(result.statistics.get("high", 0)))
    table.add_row("Medium", str(result.statistics.get("medium", 0)))
    table.add_row("Low", str(result.statistics.get("low", 0)))
    table.add_row("Info", str(result.statistics.get("info", 0)))
    
    http_reqs = result.statistics.get("http_requests", 0)
    cache_hits = result.statistics.get("cache_hits", 0)
    table.add_row("HTTP Requests", str(http_reqs))
    table.add_row("Cache Hits (dedup)", str(cache_hits))
    
    duration = (result.end_time - result.start_time).total_seconds() if result.end_time and result.start_time else 0
    table.add_row("Duration", f"{duration:.1f}s")
    
    console.print(table)
    
    # Critical findings panel
    critical_findings = [f for f in result.findings if f.severity.value == "critical"]
    if critical_findings:
        console.print(Panel(
            "\n".join([f"[red]•[/red] {f.title} - {f.url}" for f in critical_findings[:5]]),
            title=f"[bold red]CRITICAL FINDINGS ({len(critical_findings)})",
            border_style="red"
        ))
    
    # High findings panel
    high_findings = [f for f in result.findings if f.severity.value == "high"]
    if high_findings:
        console.print(Panel(
            "\n".join([f"[orange1]•[/orange1] {f.title} - {f.url}" for f in high_findings[:5]]),
            title=f"[bold orange1]HIGH FINDINGS ({len(high_findings)})",
            border_style="orange1"
        ))


@app.command()
def scan(
    url: Optional[str] = typer.Argument(None, help="Target URL(s) — single or comma-separated"),
    targets_file: Optional[str] = typer.Option(None, "-L", "--targets-file", help="File with target URLs (one per line)"),
    output: Optional[str] = typer.Option("aem_report", "-o", "--output", help="Output file base name"),
    threads: int = typer.Option(50, "-t", "--threads", help="Max concurrent threads"),
    delay: float = typer.Option(1.0, "-d", "--delay", help="Base delay between requests (seconds)"),
    timeout: int = typer.Option(30, "-T", "--timeout", help="Request timeout (seconds)"),
    proxy: Optional[str] = typer.Option(None, "-p", "--proxy", help="Proxy URL (e.g., http://proxy:8080)"),
    no_jcr: bool = typer.Option(False, "--no-jcr", help="Disable JCR probing"),
    no_osgi: bool = typer.Option(False, "--no-osgi", help="Disable OSGi testing"),
    no_injection: bool = typer.Option(False, "--no-injection", help="Disable injection testing"),
    no_cve: bool = typer.Option(False, "--no-cve", help="Disable CVE checks"),
    no_smuggler: bool = typer.Option(False, "--no-smuggler", help="Disable Sling Smuggler"),
    no_inference: bool = typer.Option(False, "--no-inference", help="Disable JCR Inference Engine"),
    no_service_probe: bool = typer.Option(False, "--no-service-probe", help="Disable service probing"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Suppress live finding output"),
    waf_evasion: bool = typer.Option(True, "--waf-evasion/--no-waf-evasion", help="Enable WAF evasion techniques"),
):
    """Run comprehensive AEM offensive security scan.
    
    Examples:
      slingblade scan https://target.com
      slingblade scan https://a.com,https://b.com
      slingblade scan -L hosts.txt
      slingblade scan https://extra.com -L hosts.txt
    """
    
    print_banner()
    
    # --- Load targets ---
    targets = load_targets(url, targets_file)
    if not targets:
        console.print("[bold red]Error:[/bold red] No targets specified. Provide a URL or use -L/--targets-file.")
        raise typer.Exit(code=1)
    
    multi = len(targets) > 1
    console.print(f"[bold green]Target{'s' if multi else ''}:[/bold green] {', '.join(targets)}")
    if multi:
        console.print(f"[dim]Scanning {len(targets)} hosts sequentially[/dim]")
    console.print("")
    
    # --- Build config ---
    config = AEMConfig()
    config.max_concurrent = threads
    config.base_delay = delay
    config.timeout = timeout
    config.proxy = proxy
    config.verbose = verbose
    config.waf_evasion = waf_evasion
    config.enable_jcr_probe = not no_jcr
    config.enable_osgi_exploit = not no_osgi
    config.enable_injection = not no_injection
    config.enable_cve_suite = not no_cve
    config.enable_sling_smuggler = not no_smuggler
    config.enable_jcr_inference = not no_inference
    config.enable_service_probe = not no_service_probe
    
    # --- Live output callback ---
    on_finding = None if quiet else _print_finding_live
    
    # --- Run scan(s) ---
    all_results: List[ScanResult] = []
    
    try:
        for idx, target_url in enumerate(targets, 1):
            if multi:
                console.print(f"\n[bold]{'─' * 60}[/bold]")
                console.print(f"[bold green]Host {idx}/{len(targets)}:[/bold green] {target_url}")
                console.print(f"[bold]{'─' * 60}[/bold]")
            
            config.target_url = target_url
            result = asyncio.run(run_scan(target_url, config, on_finding=on_finding))
            all_results.append(result)
            
            # Print per-host summary
            print_results(result)
            
            # Generate per-host reports
            host_slug = target_url.split("://", 1)[-1].replace("/", "_").replace(":", "_")[:50]
            report_base = f"{output}_{host_slug}" if multi else output
            console.print(f"\n[bold]Generating reports...[/bold]")
            generator = ReportGenerator(result)
            report_files = generator.save_reports(report_base)
            console.print(f"[green]JSON Report:[/green] {report_files['json']}")
            console.print(f"[green]HTML Report:[/green] {report_files['html']}")
            console.print(f"[green]Graphviz DOT:[/green] {report_files['dot']}")
        
        # --- Multi-host combined summary ---
        if multi:
            console.print(f"\n[bold]{'═' * 60}[/bold]")
            console.print(f"[bold green]COMBINED SUMMARY ({len(all_results)} hosts)[/bold green]")
            console.print(f"[bold]{'═' * 60}[/bold]")
            total_f = sum(len(r.findings) for r in all_results)
            total_crit = sum(r.statistics.get("critical", 0) for r in all_results)
            total_high = sum(r.statistics.get("high", 0) for r in all_results)
            total_reqs = sum(r.statistics.get("http_requests", 0) for r in all_results)
            total_cache = sum(r.statistics.get("cache_hits", 0) for r in all_results)
            
            table = Table(title="Combined Results", box=box.ROUNDED)
            table.add_column("Host", style="cyan")
            table.add_column("Findings", style="magenta", justify="right")
            table.add_column("Critical", style="red", justify="right")
            table.add_column("High", style="orange1", justify="right")
            table.add_column("Requests", style="dim", justify="right")
            
            for r in all_results:
                table.add_row(
                    r.target,
                    str(len(r.findings)),
                    str(r.statistics.get("critical", 0)),
                    str(r.statistics.get("high", 0)),
                    str(r.statistics.get("http_requests", 0)),
                )
            table.add_row(
                "[bold]TOTAL[/bold]",
                f"[bold]{total_f}[/bold]",
                f"[bold]{total_crit}[/bold]",
                f"[bold]{total_high}[/bold]",
                f"[bold]{total_reqs}[/bold]",
            )
            console.print(table)
            console.print(f"[dim]Cache hits (dedup): {total_cache}[/dim]")
        
        console.print("\n[bold green]Scan completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@app.command()
def bypass(
    url: str = typer.Argument(..., help="Target URL to test bypasses on"),
    path: str = typer.Option("/admin", "-p", "--path", help="Path to test bypasses on"),
    technique: Optional[str] = typer.Option(None, "-t", "--technique", help="Specific bypass technique to test"),
):
    """Test specific dispatcher bypass techniques."""
    
    print_banner()
    
    target_url = validate_url(url)
    console.print(f"[bold green]Target:[/bold green] {target_url}")
    console.print(f"[bold green]Path:[/bold green] {path}")
    
    bypass = BypassTransformer()
    
    if technique:
        from core.models import BypassTechnique
        try:
            tech = BypassTechnique(technique)
            variants = bypass.transform(path, tech)
        except ValueError:
            console.print(f"[red]Unknown technique: {technique}[/red]")
            console.print(f"[yellow]Available techniques:[/yellow]")
            for t in BypassTechnique:
                console.print(f"  - {t.value}")
            return
    else:
        variants = bypass.generate_all_variants(path, max_results=20)
    
    console.print(f"\n[bold]Generated {len(variants)} bypass variants:[/bold]\n")
    
    table = Table(box=box.ROUNDED)
    table.add_column("Priority", style="cyan", no_wrap=True)
    table.add_column("Technique", style="yellow")
    table.add_column("URL", style="green")
    table.add_column("Description", style="dim")
    
    for v in variants:
        table.add_row(
            str(v.priority),
            v.technique.value,
            v.url[:60] + "..." if len(v.url) > 60 else v.url,
            v.description
        )
    
    console.print(table)


@app.command()
def wordlist(
    category: str = typer.Argument("paths", help="Wordlist category (paths, selectors, extensions, components)"),
    count: int = typer.Option(20, "-n", "--count", help="Number of items to show"),
):
    """Display available wordlists."""
    
    from data.wordlists import AEMWordlists
    
    print_banner()
    
    wl = AEMWordlists
    
    if category == "paths":
        items = wl.get_all_paths()
        title = "Core AEM Paths"
    elif category == "selectors":
        items = wl.SELECTORS
        title = "Content Selectors"
    elif category == "extensions":
        items = wl.EXTENSIONS
        title = "File Extensions"
    elif category == "components":
        items = wl.get_vulnerable_components()
        title = "Vulnerable Components"
    else:
        console.print(f"[red]Unknown category: {category}[/red]")
        return
    
    console.print(f"\n[bold]{title}[/bold] (showing {min(count, len(items))} of {len(items)})\n")
    
    for i, item in enumerate(items[:count], 1):
        console.print(f"  {i:3}. {item}")
    
    if len(items) > count:
        console.print(f"\n[dim]... and {len(items) - count} more[/dim]")


@app.command()
def version():
    """Show version information."""
    console.print(f"[bold]Slingblade[/bold] v{__version__}")
    console.print(f"[dim]{__author__}[/dim]")


if __name__ == "__main__":
    app()
