"""
Adaptive Rate Limiter - Intelligent request throttling to avoid detection and respect targets.
"""
import time
import asyncio
import random
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiting."""
    # Default requests per second
    default_rps: float = 10.0
    # Minimum delay between requests (seconds)
    min_delay: float = 0.05
    # Maximum delay between requests (seconds)
    max_delay: float = 5.0
    # Initial backoff on rate limit (seconds)
    initial_backoff: float = 1.0
    # Maximum backoff (seconds)
    max_backoff: float = 60.0
    # Backoff multiplier
    backoff_multiplier: float = 2.0
    # Window size for rate calculation (seconds)
    window_size: float = 10.0
    # Enable jitter to avoid detection
    jitter_enabled: bool = True
    # Jitter range (0.0 to 1.0, percentage of delay)
    jitter_range: float = 0.2
    # Burst allowance (extra requests allowed in burst)
    burst_size: int = 5
    # Enable adaptive slowdown on errors
    adaptive_slowdown: bool = True


@dataclass
class HostState:
    """State tracking for a specific host."""
    # Token bucket for rate limiting
    tokens: float = 10.0
    last_refill: float = field(default_factory=time.time)
    # Request timestamps for sliding window
    request_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    # Current backoff state
    backoff_until: float = 0.0
    current_backoff: float = 1.0
    # Consecutive errors
    consecutive_errors: int = 0
    # Detected rate limit
    detected_rps: Optional[float] = None
    # Response time tracking for adaptive delays
    response_times: deque = field(default_factory=lambda: deque(maxlen=50))


class AdaptiveRateLimiter:
    """
    Intelligent rate limiter that adapts to target behavior.
    
    Features:
    - Token bucket algorithm with burst support
    - Exponential backoff on rate limits (429)
    - Adaptive slowdown on errors
    - Retry-After header support
    - Host-specific rate limiting
    - Jitter to avoid detection patterns
    """
    
    def __init__(self, config: Optional[RateLimiterConfig] = None):
        self.config = config or RateLimiterConfig()
        self.host_states: Dict[str, HostState] = {}
        self._lock = asyncio.Lock()
    
    def _get_host(self, url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    
    def _get_state(self, host: str) -> HostState:
        """Get or create state for a host."""
        if host not in self.host_states:
            self.host_states[host] = HostState(
                tokens=self.config.burst_size,
                current_backoff=self.config.initial_backoff
            )
        return self.host_states[host]
    
    def _refill_tokens(self, state: HostState, rps: float) -> None:
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - state.last_refill
        
        # Add tokens based on time and rate
        new_tokens = elapsed * rps
        max_tokens = self.config.burst_size + rps
        state.tokens = min(state.tokens + new_tokens, max_tokens)
        state.last_refill = now
    
    def _add_jitter(self, delay: float) -> float:
        """Add random jitter to delay."""
        if not self.config.jitter_enabled:
            return delay
        
        jitter_amount = delay * self.config.jitter_range
        return delay + random.uniform(-jitter_amount, jitter_amount)
    
    async def acquire(self, url: str) -> float:
        """
        Acquire permission to make a request.
        
        Returns the time waited (for metrics).
        Blocks until the request can be made.
        """
        host = self._get_host(url)
        wait_time = 0.0
        
        async with self._lock:
            state = self._get_state(host)
            now = time.time()
            
            # Check if in backoff
            if now < state.backoff_until:
                backoff_wait = state.backoff_until - now
                wait_time += backoff_wait
                await asyncio.sleep(backoff_wait)
                now = time.time()
            
            # Determine effective rate
            effective_rps = state.detected_rps or self.config.default_rps
            
            # Slow down on consecutive errors
            if self.config.adaptive_slowdown and state.consecutive_errors > 0:
                effective_rps = effective_rps / (1 + state.consecutive_errors * 0.5)
            
            # Refill tokens
            self._refill_tokens(state, effective_rps)
            
            # Wait if no tokens available
            if state.tokens < 1:
                token_wait = (1 - state.tokens) / effective_rps
                token_wait = min(max(token_wait, self.config.min_delay), self.config.max_delay)
                token_wait = self._add_jitter(token_wait)
                wait_time += token_wait
                await asyncio.sleep(token_wait)
                self._refill_tokens(state, effective_rps)
            
            # Consume token
            state.tokens -= 1
            state.request_times.append(time.time())
        
        return wait_time
    
    async def report_response(
        self,
        url: str,
        status_code: int,
        response_time: float,
        retry_after: Optional[int] = None
    ) -> None:
        """
        Report response for adaptive rate limiting.
        
        Args:
            url: The request URL
            status_code: HTTP status code
            response_time: Time taken for request (seconds)
            retry_after: Value from Retry-After header if present
        """
        host = self._get_host(url)
        
        async with self._lock:
            state = self._get_state(host)
            now = time.time()
            
            # Track response time
            state.response_times.append(response_time)
            
            if status_code == 429:
                # Rate limited - apply backoff
                if retry_after:
                    state.backoff_until = now + retry_after
                    state.current_backoff = retry_after
                else:
                    state.backoff_until = now + state.current_backoff
                    state.current_backoff = min(
                        state.current_backoff * self.config.backoff_multiplier,
                        self.config.max_backoff
                    )
                
                # Try to detect actual rate limit
                if len(state.request_times) >= 10:
                    recent_requests = list(state.request_times)[-10:]
                    time_span = recent_requests[-1] - recent_requests[0]
                    if time_span > 0:
                        observed_rps = len(recent_requests) / time_span
                        state.detected_rps = observed_rps * 0.7  # Back off to 70% of detected
                
                state.consecutive_errors += 1
                
            elif status_code >= 500:
                # Server error - mild backoff
                state.consecutive_errors += 1
                if state.consecutive_errors >= 3:
                    state.backoff_until = now + self.config.initial_backoff
                    
            elif status_code < 400:
                # Success - reset backoff
                state.consecutive_errors = 0
                state.current_backoff = self.config.initial_backoff
                
                # Gradually increase rate if stable
                if state.detected_rps and state.detected_rps < self.config.default_rps:
                    state.detected_rps = min(
                        state.detected_rps * 1.05,
                        self.config.default_rps
                    )
    
    def get_stats(self, url: str) -> Dict:
        """Get rate limiting statistics for a host."""
        host = self._get_host(url)
        state = self._get_state(host)
        
        # Calculate average response time
        avg_response_time = None
        if state.response_times:
            avg_response_time = sum(state.response_times) / len(state.response_times)
        
        # Calculate actual request rate
        actual_rps = None
        if len(state.request_times) >= 2:
            recent = list(state.request_times)[-20:]
            if len(recent) >= 2:
                time_span = recent[-1] - recent[0]
                if time_span > 0:
                    actual_rps = (len(recent) - 1) / time_span
        
        return {
            "host": host,
            "tokens_available": state.tokens,
            "configured_rps": self.config.default_rps,
            "detected_rps": state.detected_rps,
            "actual_rps": actual_rps,
            "consecutive_errors": state.consecutive_errors,
            "in_backoff": time.time() < state.backoff_until,
            "backoff_remaining": max(0, state.backoff_until - time.time()),
            "avg_response_time": avg_response_time,
            "total_requests": len(state.request_times)
        }
    
    def reset(self, url: Optional[str] = None) -> None:
        """Reset rate limiter state."""
        if url:
            host = self._get_host(url)
            if host in self.host_states:
                del self.host_states[host]
        else:
            self.host_states.clear()


# Global rate limiter instance
_global_rate_limiter: Optional[AdaptiveRateLimiter] = None


def get_rate_limiter() -> AdaptiveRateLimiter:
    """Get the global rate limiter instance."""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = AdaptiveRateLimiter()
    return _global_rate_limiter


def configure_rate_limiter(config: RateLimiterConfig) -> None:
    """Configure the global rate limiter."""
    global _global_rate_limiter
    _global_rate_limiter = AdaptiveRateLimiter(config)
