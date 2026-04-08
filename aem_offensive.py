#!/usr/bin/env python3
"""Slingblade - AEM Offensive Security Framework

A sharp tool for penetrating Adobe Experience Manager defenses.
Multi-phase discovery, bypass techniques, and deep service probing.
"""

import asyncio
import sys
from datetime import datetime
from typing import Optional

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


def validate_url(url: str) -> str:
    """Validate and normalize URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


async def run_scan(target_url: str, config: AEMConfig) -> ScanResult:
    """Execute the full scan workflow."""
    
    start_time = datetime.utcnow()
    
    # Initialize result container
    result = ScanResult(
        target=target_url,
        start_time=start_time,
        target_info=TargetInfo(url=target_url)
    )
    
    # Initialize bypass transformer
    bypass = BypassTransformer()
    
    async with HTTPXEngine(config) as engine:
        # Calibrate soft-404 detection before scanning
        await engine.calibrate_soft_404(target_url)
        
        # Phase Manager for discovery
        phase_manager = PhaseManager(engine, config)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Phase 1-3: Multi-phase discovery
            task = progress.add_task("[cyan]Running multi-phase discovery...", total=None)
            phase_results = await phase_manager.run_all_phases(target_url)
            progress.remove_task(task)
            
            # Collect all phase findings
            for phase_result in phase_results:
                result.findings.extend(phase_result.findings)
                if phase_result.target_info:
                    result.target_info = phase_result.target_info
                # Check for abort after phases
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
                    break
            
            # JCR Probing Module
            if config.enable_jcr_probe and not engine.should_abort:
                task = progress.add_task("[green]Probing JCR resources...", total=None)
                jcr_module = JCRProbingModule(engine, config, bypass)
                jcr_findings = await jcr_module.run(target_url)
                result.findings.extend(jcr_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
            
            # OSGi Exploitation Module
            if config.enable_osgi_exploit and not engine.should_abort:
                task = progress.add_task("[yellow]Testing OSGi exploitation...", total=None)
                osgi_module = OSGiExploitationModule(engine, config, bypass)
                osgi_findings = await osgi_module.run(target_url)
                result.findings.extend(osgi_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
            
            # Injection Testing Module
            if config.enable_injection and not engine.should_abort:
                task = progress.add_task("[red]Testing injection vectors...", total=None)
                injection_module = InjectionTestingModule(engine, config)
                injection_findings = await injection_module.run(target_url)
                result.findings.extend(injection_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
            
            # CVE Suite Module
            if config.enable_cve_suite and not engine.should_abort:
                task = progress.add_task("[magenta]Running CVE checks...", total=None)
                cve_module = CVESuiteModule(engine, config, bypass)
                cve_findings = await cve_module.run(target_url)
                result.findings.extend(cve_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
            
            # Sling Smuggler Module
            if config.enable_sling_smuggler and not engine.should_abort:
                task = progress.add_task("[blue]Running Sling Smuggler permutations...", total=None)
                smuggler = SlingSmuggler(engine, config, bypass)
                smuggler_findings = await smuggler.run(target_url)
                result.findings.extend(smuggler_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
            
            # JCR Inference Engine Module
            if config.enable_jcr_inference and not engine.should_abort:
                task = progress.add_task("[cyan]Running JCR Inference Engine...", total=None)
                inference = JCRInferenceEngine(engine, config, bypass)
                inference_findings = await inference.run(target_url)
                result.findings.extend(inference_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
            
            # Service Probe Module
            if config.enable_service_probe and not engine.should_abort:
                task = progress.add_task("[white]Probing AEM services...", total=None)
                service_probe = ServiceProbeModule(engine, config, bypass)
                service_findings = await service_probe.run(target_url)
                result.findings.extend(service_findings)
                progress.remove_task(task)
                if engine.should_abort:
                    print("[yellow]Scan aborted due to excessive failures[/yellow]")
    
    # Calculate end time
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
    url: str = typer.Argument(..., help="Target AEM URL (e.g., https://example.com)"),
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
    waf_evasion: bool = typer.Option(True, "--waf-evasion/--no-waf-evasion", help="Enable WAF evasion techniques"),
):
    """Run comprehensive AEM offensive security scan."""
    
    print_banner()
    
    # Validate URL
    target_url = validate_url(url)
    console.print(f"[bold green]Target:[/bold green] {target_url}")
    
    # Configure scan
    config = AEMConfig()
    config.target_url = target_url
    config.max_concurrent = threads
    config.base_delay = delay
    config.timeout = timeout
    config.proxy = proxy
    config.verbose = verbose
    config.waf_evasion = waf_evasion
    
    # Module toggles
    config.enable_jcr_probe = not no_jcr
    config.enable_osgi_exploit = not no_osgi
    config.enable_injection = not no_injection
    config.enable_cve_suite = not no_cve
    config.enable_sling_smuggler = not no_smuggler
    config.enable_jcr_inference = not no_inference
    config.enable_service_probe = not no_service_probe
    
    # Run scan
    try:
        result = asyncio.run(run_scan(target_url, config))
        
        # Print results
        print_results(result)
        
        # Generate reports
        console.print("\n[bold]Generating reports...[/bold]")
        generator = ReportGenerator(result)
        report_files = generator.save_reports(output)
        
        console.print(f"[green]JSON Report:[/green] {report_files['json']}")
        console.print(f"[green]HTML Report:[/green] {report_files['html']}")
        console.print(f"[green]Graphviz DOT:[/green] {report_files['dot']}")
        
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
