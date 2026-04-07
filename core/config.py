"""Configuration management for AEM Offensive Framework."""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class AEMConfig:
    """Global configuration for the framework."""
    
    # Target settings
    target_url: str = ""
    timeout: int = 30
    max_retries: int = 3
    
    # Concurrency
    max_concurrent: int = 50
    semaphore_limit: int = 100
    
    # Rate limiting
    base_delay: float = 1.0
    adaptive_rate_limit: bool = True
    waf_evasion: bool = True
    
    # Discovery settings
    max_depth: int = 3
    max_child_nodes: int = 100
    infinity_safety_threshold: int = 1000
    
    # Reporting
    output_format: str = "json"
    output_file: Optional[str] = None
    verbose: bool = False
    
    # Module toggles
    enable_fingerprinting: bool = True
    enable_jcr_probe: bool = True
    enable_osgi_exploit: bool = True
    enable_injection: bool = True
    enable_cve_suite: bool = True
    enable_sling_smuggler: bool = True
    enable_jcr_inference: bool = True
    enable_service_probe: bool = True
    
    # Proxy settings
    proxy: Optional[str] = None
    
    # Wordlist paths (can be customized)
    custom_wordlist: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "AEMConfig":
        """Load configuration from environment variables."""
        config = cls()
        config.timeout = int(os.getenv("AEM_TIMEOUT", "30"))
        config.max_concurrent = int(os.getenv("AEM_CONCURRENT", "50"))
        config.base_delay = float(os.getenv("AEM_DELAY", "1.0"))
        config.proxy = os.getenv("AEM_PROXY")
        config.verbose = os.getenv("AEM_VERBOSE", "false").lower() == "true"
        return config
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary."""
        return {
            k: v for k, v in self.__dict__.items()
            if not k.startswith("_")
        }


# Default HTTP headers for evasion
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# User-Agent rotation pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# X-Forwarded-For IP pool for IP spoofing
X_FORWARDED_IPS = [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "::1",
    "169.254.169.254",  # AWS metadata
]
