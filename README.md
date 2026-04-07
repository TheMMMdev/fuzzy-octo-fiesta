# AEM Multi-Stage Offensive Security Framework

A comprehensive, asynchronous offensive security tool for Adobe Experience Manager (AEM) audits with advanced vulnerability chaining capabilities.

## Architecture

```
aem_offensive/
├── core/
│   ├── __init__.py
│   ├── config.py          # Configuration management
│   ├── models.py          # Pydantic data models
│   ├── engine.py          # Async HTTP engine with rate limiting
│   └── phases.py          # Multi-phase discovery system
├── bypass/
│   ├── __init__.py
│   └── transformers.py    # Bypass engine with all techniques
├── modules/
│   ├── __init__.py
│   ├── fingerprint.py     # Phase 1: Dispatcher & server fingerprinting
│   ├── discovery.py       # Phase 2: Contextual path discovery
│   ├── jcr_probe.py       # JCR & Sling resource probing
│   ├── osgi_exploit.py    # OSGi exploitation
│   ├── injection.py       # SSTI, SSRF, LFI testing
│   └── cve_suite.py       # CVE & N-Day checks
├── reporting/
│   ├── __init__.py
│   └── attack_graph.py    # Attack graph generation
├── data/
│   └── wordlists.py       # Extensive AEM wordlists
├── aem_offensive.py       # Main entry point
└── requirements.txt       # Dependencies
```

## Features

- **Multi-Phase Discovery**: Fingerprinting → Contextual Discovery → Payload Injection
- **Bypass Engine**: Semicolon injections, double extensions, encoding, selector smuggling
- **JCR Probing**: Recursive dumps with safety brakes, child node enumeration
- **OSGi Exploitation**: Console detection, Groovy Console, CRXDE Lite checks
- **Injection Testing**: SSTI, SSRF, LFI via Sling selectors
- **CVE Suite**: CVE-2019-7964, CVE-2016-0957, and N-day patterns
- **Adaptive Rate Limiting**: WAF evasion with smart timing
- **Attack Graph Reporting**: Visual vulnerability chains

## Usage

```bash
python aem_offensive.py -u https://target.com -o report.json --threads 50
```

## Installation

```bash
pip install -r requirements.txt
```

## Requirements

- Python 3.11+
- httpx (async HTTP/2)
- pydantic (data validation)
- networkx (attack graph)
