"""
Adaptive Rate Limiter - Intelligent request throttling to avoid detection and respect targets.
"""
import asyncio
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger

logger = get_logger(__name__)


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


class RateLimitError(Exception):
    """Exception raised when rate limiting fails."""
    pass


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
    
    def __init__(self, config: Optional[RateLimiterConfig] = None) -> None:
        """
        Initialize adaptive rate limiter.
        
        Args:
            config: Rate limiter configuration (uses defaults if not provided)
        """
        self.config = config or RateLimiterConfig()
        self.host_states: Dict[str, HostState] = {}
        self._lock = asyncio.Lock()
        
        logger.info(
            "Rate limiter initialized",
            extra={
                "default_rps": self.config.default_rps,
                "burst_size": self.config.burst_size,
                "jitter_enabled": self.config.jitter_enabled
            }
        )
    
    def _get_host(self, url: str) -> str:
        """
        Extract host from URL.
        
        Args:
            url: Full URL or hostname
        
        Returns:
            Hostname/netloc portion
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except Exception as e:
            logger.warning(f"Failed to parse URL '{url}': {e}")
            return url
    
    def _get_state(self, host: str) -> HostState:
        """
        Get or create state for a host.
        
        Args:
            host: Hostname
        
        Returns:
            HostState object for the host
        """
        if host not in self.host_states:
            self.host_states[host] = HostState(
                tokens=self.config.burst_size,
                current_backoff=self.config.initial_backoff
            )
            logger.debug(f"Created new rate limit state for host: {host}")
        return self.host_states[host]
    
    def _refill_tokens(self, state: HostState, rps: float) -> None:
        """
        Refill tokens based on time elapsed.
        
        Args:
            state: Host state to refill
            rps: Requests per second rate
        """
        now = time.time()
        elapsed = now - state.last_refill
        
        # Add tokens based on time and rate
        new_tokens = elapsed * rps
        max_tokens = self.config.burst_size + rps
        state.tokens = min(state.tokens + new_tokens, max_tokens)
        state.last_refill = now
    
    def _add_jitter(self, delay: float) -> float:
        """
        Add random jitter to delay to avoid detection patterns.
        
        Args:
            delay: Base delay in seconds
        
        Returns:
            Delay with jitter applied
        """
        if not self.config.jitter_enabled:
            return delay
        
        jitter_amount = delay * self.config.jitter_range
        jittered_delay = delay + random.uniform(-jitter_amount, jitter_amount)
        
        # Ensure delay stays within bounds
        return max(self.config.min_delay, min(jittered_delay, self.config.max_delay))
    
    async def acquire(self, url: str) -> float:
        """
        Acquire permission to make a request.
        
        This method will block until the request can be made according
        to the rate limiting policy.
        
        Args:
            url: URL to make request to (used for host-specific limiting)
        
        Returns:
            Time waited in seconds (useful for metrics)
        
        Raises:
            RateLimitError: If rate limiting fails
        """
        host = self._get_host(url)
        wait_time = 0.0
        
        try:
            async with self._lock:
                state = self._get_state(host)
                now = time.time()
                
                # Check if in backoff period
                if now < state.backoff_until:
                    backoff_wait = state.backoff_until - now
                    logger.debug(
                        f"Host in backoff: {host}",
                        extra={"host": host, "backoff_seconds": backoff_wait}
                    )
                    wait_time += backoff_wait
                    await asyncio.sleep(backoff_wait)
                    now = time.time()
                
                # Determine effective rate
                effective_rps = state.detected_rps or self.config.default_rps
                
                # Apply adaptive slowdown on consecutive errors
                if self.config.adaptive_slowdown and state.consecutive_errors > 0:
                    slowdown_factor = 1 + state.consecutive_errors * 0.5
                    effective_rps = effective_rps / slowdown_factor
                    logger.debug(
                        f"Adaptive slowdown applied for {host}",
                        extra={
                            "host": host,
                            "consecutive_errors": state.consecutive_errors,
                            "effective_rps": effective_rps
                        }
                    )
                
                # Refill tokens
                self._refill_tokens(state, effective_rps)
                
                # Wait if no tokens available
                if state.tokens < 1:
                    token_wait = (1 - state.tokens) / effective_rps
                    token_wait = min(max(token_wait, self.config.min_delay), self.config.max_delay)
                    token_wait = self._add_jitter(token_wait)
                    
                    logger.debug(
                        f"Rate limit wait for {host}",
                        extra={"host": host, "wait_seconds": token_wait}
                    )
                    
                    wait_time += token_wait
                    await asyncio.sleep(token_wait)
                    self._refill_tokens(state, effective_rps)
                
                # Consume token
                state.tokens -= 1
                state.request_times.append(time.time())
                
                if wait_time > 0:
                    logger.debug(
                        f"Request acquired for {host} after {wait_time:.3f}s wait",
                        extra={"host": host, "total_wait": wait_time}
                    )
        
        except asyncio.CancelledError:
            logger.warning(f"Rate limiter acquire cancelled for {host}")
            raise
        except Exception as e:
            logger.error(f"Rate limiter acquire failed for {host}: {e}", exc_info=True)
            raise RateLimitError(f"Failed to acquire rate limit token: {str(e)}")
        
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
        
        This allows the rate limiter to adapt its behavior based on
        server responses.
        
        Args:
            url: The request URL
            status_code: HTTP status code
            response_time: Time taken for request in seconds
            retry_after: Value from Retry-After header if present
        """
        host = self._get_host(url)
        
        try:
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
                        logger.warning(
                            f"Rate limited by {host} - respecting Retry-After: {retry_after}s",
                            extra={"host": host, "retry_after": retry_after}
                        )
                    else:
                        state.backoff_until = now + state.current_backoff
                        state.current_backoff = min(
                            state.current_backoff * self.config.backoff_multiplier,
                            self.config.max_backoff
                        )
                        logger.warning(
                            f"Rate limited by {host} - backing off for {state.current_backoff}s",
                            extra={"host": host, "backoff": state.current_backoff}
                        )
                    
                    # Try to detect actual rate limit
                    if len(state.request_times) >= 10:
                        recent_requests = list(state.request_times)[-10:]
                        time_span = recent_requests[-1] - recent_requests[0]
                        if time_span > 0:
                            observed_rps = len(recent_requests) / time_span
                            state.detected_rps = observed_rps * 0.7  # Back off to 70% of detected
                            logger.info(
                                f"Detected rate limit for {host}: {observed_rps:.2f} RPS, "
                                f"adjusting to {state.detected_rps:.2f} RPS",
                                extra={
                                    "host": host,
                                    "observed_rps": observed_rps,
                                    "adjusted_rps": state.detected_rps
                                }
                            )
                    
                    state.consecutive_errors += 1
                    
                elif status_code >= 500:
                    # Server error - mild backoff
                    state.consecutive_errors += 1
                    
                    if state.consecutive_errors >= 3:
                        state.backoff_until = now + self.config.initial_backoff
                        logger.warning(
                            f"Multiple server errors from {host} ({state.consecutive_errors}), "
                            f"backing off for {self.config.initial_backoff}s",
                            extra={"host": host, "consecutive_errors": state.consecutive_errors}
                        )
                    
                elif status_code < 400:
                    # Success - reset backoff
                    if state.consecutive_errors > 0:
                        logger.debug(
                            f"Successful response from {host}, resetting error count",
                            extra={"host": host, "previous_errors": state.consecutive_errors}
                        )
                    
                    state.consecutive_errors = 0
                    state.current_backoff = self.config.initial_backoff
                    
                    # Gradually increase rate if stable
                    if state.detected_rps and state.detected_rps < self.config.default_rps:
                        old_rps = state.detected_rps
                        state.detected_rps = min(
                            state.detected_rps * 1.05,
                            self.config.default_rps
                        )
                        if state.detected_rps != old_rps:
                            logger.debug(
                                f"Gradually increasing rate for {host}: "
                                f"{old_rps:.2f} -> {state.detected_rps:.2f} RPS",
                                extra={"host": host, "new_rps": state.detected_rps}
                            )
        
        except Exception as e:
            logger.error(f"Failed to report response for {host}: {e}", exc_info=True)
    
    def get_stats(self, url: str) -> Dict[str, any]:
        """
        Get rate limiting statistics for a host.
        
        Args:
            url: URL or hostname to get stats for
        
        Returns:
            Dictionary with statistics
        """
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
        """
        Reset rate limiter state.
        
        Args:
            url: Specific URL/host to reset, or None to reset all
        """
        if url:
            host = self._get_host(url)
            if host in self.host_states:
                del self.host_states[host]
                logger.info(f"Reset rate limiter state for host: {host}")
        else:
            num_hosts = len(self.host_states)
            self.host_states.clear()
            logger.info(f"Reset rate limiter state for all {num_hosts} hosts")


# Global rate limiter instance
_global_rate_limiter: Optional[AdaptiveRateLimiter] = None


def get_rate_limiter() -> AdaptiveRateLimiter:
    """
    Get the global rate limiter instance.
    
    Returns:
        Global AdaptiveRateLimiter instance
    """
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = AdaptiveRateLimiter()
        logger.debug("Created global rate limiter instance")
    return _global_rate_limiter


def configure_rate_limiter(config: RateLimiterConfig) -> None:
    """
    Configure the global rate limiter.
    
    Args:
        config: New rate limiter configuration
    """
    global _global_rate_limiter
    _global_rate_limiter = AdaptiveRateLimiter(config)
    logger.info("Global rate limiter reconfigured", extra={"config": config})


def reset_rate_limiter() -> None:
    """Reset the global rate limiter instance (mainly for testing)."""
    global _global_rate_limiter
    if _global_rate_limiter:
        _global_rate_limiter.reset()
    logger.debug("Global rate limiter reset")