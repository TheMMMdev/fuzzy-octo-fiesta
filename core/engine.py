"""Async HTTP engine with adaptive rate limiting for AEM Offensive Framework."""

import asyncio
import random
import time
from typing import Any, Dict, Optional, List
from dataclasses import dataclass

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
            
            return ResponseWrapper(
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                url=str(response.url),
                elapsed=elapsed,
                bypass_used=bypass,
                technique=technique
            )
            
        except httpx.RequestError as e:
            self.stats["errors"] += 1
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
        
        if response.status_code not in [401, 403, 404] or bypass_transformer is None:
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
            
            if bypass_response.status_code == 200 and len(bypass_response.text) > 0:
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
