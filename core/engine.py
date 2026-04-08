"""Async HTTP engine with adaptive rate limiting for AEM Offensive Framework."""

import asyncio
import hashlib
import random
import time
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field

import httpx
from core.config import AEMConfig, DEFAULT_HEADERS, USER_AGENTS, X_FORWARDED_IPS
from core.models import RateLimitConfig


@dataclass
class ResponseWrapper:
    """Wrapper for HTTP responses with metadata."""
    status_code: int
    headers: Dict[str, str]
    text: str
    url: str
    elapsed: float
    bypass_used: Optional[str] = None
    technique: Optional[str] = None
    is_soft_404: bool = False


class AdaptiveRateLimiter:
    """Adaptive rate limiter with WAF evasion."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.current_delay = config.base_delay
        self.consecutive_429s = 0
        self.last_request_time = 0
        self.semaphore = asyncio.Semaphore(config.burst_size)
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire rate limit slot with adaptive delays."""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time
            
            if elapsed < self.current_delay:
                delay = self.current_delay - elapsed
                if self.config.jitter:
                    delay *= random.uniform(0.8, 1.2)
                await asyncio.sleep(delay)
            
            self.last_request_time = time.time()
    
    def record_success(self):
        """Record successful request - decrease delay gradually."""
        self.consecutive_429s = 0
        if self.config.adaptive:
            self.current_delay = max(
                self.config.min_delay,
                self.current_delay * 0.95
            )
    
    def record_rate_limit(self):
        """Record rate limit hit - increase delay."""
        self.consecutive_429s += 1
        if self.config.adaptive:
            backoff = min(2 ** self.consecutive_429s, 4)
            self.current_delay = min(
                self.config.max_delay,
                self.current_delay * backoff
            )


class HTTPXEngine:
    """Async HTTP engine using httpx with HTTP/2 support."""
    
    MAX_CONSECUTIVE_FAILURES = 50  # Global abort threshold
    
    # Common soft-404 URL patterns
    SOFT_404_URL_PATTERNS = ["/404", "/error", "/not-found", "/page-not-found"]
    
    def __init__(self, config: AEMConfig):
        self.config = config
        self.rate_limiter = AdaptiveRateLimiter(
            RateLimitConfig(
                base_delay=config.base_delay,
                adaptive=config.adaptive_rate_limit,
                jitter=config.waf_evasion
            )
        )
        self.client: Optional[httpx.AsyncClient] = None
        self.stats = {
            "total_requests": 0,
            "successful": 0,
            "rate_limited": 0,
            "errors": 0
        }
        self.consecutive_failures = 0
        self._abort_scan = False
        self._abort_message_printed = False
        # Soft 404 fingerprints
        self._soft_404_hash: Optional[str] = None
        self._soft_404_length: Optional[int] = None
        self._soft_404_calibrated = False
    
    @property
    def should_abort(self) -> bool:
        """Check if scan should abort due to too many consecutive failures."""
        return self._abort_scan or self.consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES
    
    def _record_request_result(self, status_code: int, is_error: bool = False):
        """Record request result and track consecutive failures."""
        if is_error or status_code == 0:
            # Connection error or timeout
            self.consecutive_failures += 1
        elif status_code >= 500:
            # Server error (5xx) — count as failure
            self.consecutive_failures += 1
        elif status_code in [401, 403, 404]:
            # Expected HTTP responses — don't count as failure
            pass
        else:
            # Success (2xx) or client error (4xx other than 401/403/404)
            self.consecutive_failures = 0
        
        # Check if we should abort (print message only once)
        if self.consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES and not self._abort_message_printed:
            self._abort_scan = True
            self._abort_message_printed = True
            print(f"[!] ABORTING SCAN: {self.consecutive_failures} consecutive failures. Target appears unresponsive.")
    
    async def __aenter__(self):
        """Async context manager entry."""
        limits = httpx.Limits(
            max_connections=self.config.semaphore_limit,
            max_keepalive_connections=20
        )
        timeout = httpx.Timeout(self.config.timeout, connect=10.0)
        
        self.client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            http2=True,
            follow_redirects=True,
            verify=False,
            proxy=self.config.proxy
        )
        return self
    
    async def calibrate_soft_404(self, base_url: str):
        """Probe a non-existent path to fingerprint the target's soft 404 page."""
        canary = f"/slingblade-nonexistent-{random.randint(100000,999999)}.json"
        try:
            response = await self.client.request(
                "GET", f"{base_url}{canary}",
                headers=self._generate_headers()
            )
            if response.status_code == 200:
                body = response.text
                self._soft_404_hash = hashlib.md5(body.encode(errors='replace')).hexdigest()
                self._soft_404_length = len(body)
                self._soft_404_calibrated = True
                print(f"[*] Soft-404 calibrated: hash={self._soft_404_hash[:12]}... len={self._soft_404_length}")
            else:
                self._soft_404_calibrated = True
                print(f"[*] Target returns {response.status_code} for non-existent paths (no soft-404)")
        except Exception:
            self._soft_404_calibrated = True
    
    def _check_soft_404(self, response_url: str, response_text: str, request_url: str) -> bool:
        """Detect if a 200 response is actually a soft 404."""
        # Check 1: Response URL redirected to a 404 page
        response_url_lower = response_url.lower()
        request_url_lower = request_url.lower()
        if response_url_lower != request_url_lower:
            for pattern in self.SOFT_404_URL_PATTERNS:
                if pattern in response_url_lower:
                    return True
        
        # Check 2: Response body matches calibrated soft 404 fingerprint
        if self._soft_404_calibrated and self._soft_404_hash:
            body_hash = hashlib.md5(response_text.encode(errors='replace')).hexdigest()
            if body_hash == self._soft_404_hash:
                return True
            # Also check length similarity (within 5%) for dynamic soft 404s
            if self._soft_404_length and self._soft_404_length > 100:
                ratio = abs(len(response_text) - self._soft_404_length) / self._soft_404_length
                if ratio < 0.05:
                    return True
        
        return False
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()
    
    def _generate_headers(self, extra_headers: Optional[Dict] = None) -> Dict[str, str]:
        """Generate randomized headers for WAF evasion."""
        headers = DEFAULT_HEADERS.copy()
        
        if self.config.waf_evasion:
            headers["User-Agent"] = random.choice(USER_AGENTS)
            headers["X-Forwarded-For"] = random.choice(X_FORWARDED_IPS)
            headers["X-Real-IP"] = random.choice(X_FORWARDED_IPS)
            
            # Randomize Accept header slightly
            if random.random() > 0.5:
                headers["Accept"] = "application/json,text/plain,*/*"
        
        if extra_headers:
            headers.update(extra_headers)
        
        return headers
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        bypass: Optional[str] = None,
        technique: Optional[str] = None,
        **kwargs
    ) -> ResponseWrapper:
        """Make async HTTP request with rate limiting."""
        # Short-circuit if scan should abort
        if self.should_abort:
            return ResponseWrapper(
                status_code=0,
                headers={},
                text="Scan aborted due to excessive failures",
                url=url,
                elapsed=0,
                bypass_used=bypass,
                technique=technique
            )
        
        await self.rate_limiter.acquire()
        
        request_headers = self._generate_headers(headers)
        start_time = time.time()
        
        try:
            response = await self.client.request(
                method=method,
                url=url,
                headers=request_headers,
                **kwargs
            )
            
            elapsed = time.time() - start_time
            self.stats["total_requests"] += 1
            
            if response.status_code == 429:
                self.rate_limiter.record_rate_limit()
                self.stats["rate_limited"] += 1
            else:
                self.rate_limiter.record_success()
                if response.status_code < 400:
                    self.stats["successful"] += 1
            
            # Track consecutive failures
            self._record_request_result(response.status_code)
            
            resp_url = str(response.url)
            resp_text = response.text
            soft_404 = (response.status_code == 200 and 
                        self._check_soft_404(resp_url, resp_text, url))
            
            return ResponseWrapper(
                status_code=response.status_code,
                headers=dict(response.headers),
                text=resp_text,
                url=resp_url,
                elapsed=elapsed,
                bypass_used=bypass,
                technique=technique,
                is_soft_404=soft_404
            )
            
        except httpx.RequestError as e:
            self.stats["errors"] += 1
            # Track consecutive failures
            self._record_request_result(0, is_error=True)
            return ResponseWrapper(
                status_code=0,
                headers={},
                text=str(e),
                url=url,
                elapsed=time.time() - start_time,
                bypass_used=bypass,
                technique=technique
            )
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict] = None,
        bypass: Optional[str] = None,
        technique: Optional[str] = None
    ) -> ResponseWrapper:
        """Convenience GET request method."""
        return await self.request("GET", url, headers, bypass, technique)
    
    async def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        bypass: Optional[str] = None,
        technique: Optional[str] = None
    ) -> ResponseWrapper:
        """Convenience POST request method."""
        return await self.request(
            "POST", url, headers, bypass, technique, data=data, json=json
        )
    
    async def get_with_bypass_fallback(
        self,
        url: str,
        base_url: str,
        path: str,
        bypass_transformer=None,
        max_bypass_attempts: int = 30,
        headers: Optional[Dict] = None
    ) -> ResponseWrapper:
        """GET request with automatic bypass fallback on 403/401/404.
        
        If the initial request is blocked, automatically tries bypass
        variants from the BypassTransformer before giving up.
        """
        response = await self.get(url, headers=headers)
        
        # Treat soft 404 as a block
        is_blocked = response.status_code in [401, 403, 404] or response.is_soft_404
        
        if not is_blocked or bypass_transformer is None:
            return response
        
        # Blocked — try bypass variants
        variants = bypass_transformer.generate_all_variants(path, max_results=max_bypass_attempts)
        
        for variant in variants:
            bypass_url = f"{base_url}{variant.url}"
            bypass_response = await self.get(
                bypass_url,
                headers=headers,
                bypass=variant.technique.value,
                technique=variant.description
            )
            
            if (bypass_response.status_code == 200 and 
                    len(bypass_response.text) > 0 and
                    not bypass_response.is_soft_404):
                return bypass_response
        
        # All bypasses failed — return original response
        return response
    
    async def batch_requests(
        self,
        urls: List[str],
        method: str = "GET",
        max_concurrent: Optional[int] = None
    ) -> List[ResponseWrapper]:
        """Execute batch requests with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent or self.config.max_concurrent)
        
        async def _fetch(url: str) -> ResponseWrapper:
            async with semaphore:
                return await self.request(method, url)
        
        tasks = [_fetch(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)
