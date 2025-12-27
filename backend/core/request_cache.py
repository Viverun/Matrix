"""
Request Cache - Intelligent caching layer to reduce redundant HTTP requests during scanning.
"""
import asyncio
import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from core.logger import get_logger

logger = get_logger(__name__)


class CachePolicy(str, Enum):
    """Cache eviction policies."""
    LRU = "lru"  # Least Recently Used
    TTL = "ttl"  # Time-To-Live based
    LFU = "lfu"  # Least Frequently Used


@dataclass
class CacheEntry:
    """A cached response entry."""
    response_text: str
    status_code: int
    headers: Dict[str, str]
    created_at: float
    expires_at: float
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    content_hash: str = ""


@dataclass
class CacheConfig:
    """Configuration for the request cache."""
    # Maximum entries in cache
    max_entries: int = 1000
    # Default TTL in seconds
    default_ttl: float = 300.0
    # TTL for error responses
    error_ttl: float = 60.0
    # TTL for redirect responses
    redirect_ttl: float = 120.0
    # Enable caching
    enabled: bool = True
    # Cache policy
    policy: CachePolicy = CachePolicy.LRU
    # Max response size to cache (bytes)
    max_response_size: int = 1024 * 1024  # 1MB
    # Cache GET requests only
    get_only: bool = False
    # Respect Cache-Control headers
    respect_cache_headers: bool = True


class CacheError(Exception):
    """Base exception for cache errors."""
    pass


class RequestCache:
    """
    HTTP response cache for security scanning.
    
    Features:
    - Configurable TTL (Time To Live)
    - LRU/LFU/TTL eviction policies
    - Request deduplication
    - Content-based deduplication
    - Cache statistics and monitoring
    - Thundering herd prevention
    """
    
    def __init__(self, config: Optional[CacheConfig] = None) -> None:
        """
        Initialize request cache.
        
        Args:
            config: Cache configuration (uses defaults if not provided)
        """
        self.config = config or CacheConfig()
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._content_hashes: Dict[str, str] = {}  # content_hash -> cache_key
        self._pending: Dict[str, asyncio.Event] = {}  # Prevent thundering herd
        self._lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "duplicates_avoided": 0,
            "bytes_saved": 0
        }
        
        logger.info(
            "Request cache initialized",
            extra={
                "max_entries": self.config.max_entries,
                "default_ttl": self.config.default_ttl,
                "policy": self.config.policy.value,
                "enabled": self.config.enabled
            }
        )
    
    def _make_key(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> str:
        """
        Generate a cache key from request parameters.
        
        Args:
            url: Request URL
            method: HTTP method
            params: Query parameters
            data: Request body data
            headers: Request headers
        
        Returns:
            MD5 hash of the combined parameters
        """
        key_parts = [method.upper(), url]
        
        if params:
            sorted_params = sorted(params.items())
            key_parts.append(str(sorted_params))
        
        if data and method.upper() in ("POST", "PUT", "PATCH"):
            sorted_data = sorted(data.items()) if isinstance(data, dict) else [str(data)]
            key_parts.append(str(sorted_data))
        
        # Include relevant headers that might affect response
        if headers:
            relevant_headers = {
                k: v for k, v in headers.items()
                if k.lower() in ('accept', 'accept-language', 'authorization')
            }
            if relevant_headers:
                key_parts.append(str(sorted(relevant_headers.items())))
        
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _hash_content(self, content: str) -> str:
        """
        Generate hash of response content.
        
        Args:
            content: Response content
        
        Returns:
            SHA256 hash (first 16 characters)
        """
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _get_ttl(self, status_code: int, response_headers: Dict[str, str]) -> float:
        """
        Determine TTL based on response characteristics.
        
        Args:
            status_code: HTTP status code
            response_headers: Response headers
        
        Returns:
            TTL in seconds (0 means don't cache)
        """
        # Check Cache-Control header
        if self.config.respect_cache_headers:
            cache_control = response_headers.get('Cache-Control', '').lower()
            
            if 'no-store' in cache_control or 'no-cache' in cache_control:
                logger.debug("Skipping cache due to Cache-Control directive")
                return 0  # Don't cache
            
            # Parse max-age
            if 'max-age=' in cache_control:
                try:
                    max_age_str = cache_control.split('max-age=')[1].split(',')[0].strip()
                    max_age = int(max_age_str)
                    ttl = min(max_age, self.config.default_ttl)
                    logger.debug(
                        f"Using Cache-Control max-age: {ttl}s",
                        extra={"max_age": max_age, "effective_ttl": ttl}
                    )
                    return ttl
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse Cache-Control max-age: {e}")
        
        # Status-based TTL
        if status_code >= 500:
            return self.config.error_ttl
        elif status_code in (301, 302, 303, 307, 308):
            return self.config.redirect_ttl
        elif status_code >= 400:
            return self.config.error_ttl
        
        return self.config.default_ttl
    
    async def get(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> Optional[CacheEntry]:
        """
        Get cached response if available and valid.
        
        Args:
            url: Request URL
            method: HTTP method
            params: Query parameters
            data: Request body data
            headers: Request headers
        
        Returns:
            CacheEntry if found and valid, None otherwise
        """
        if not self.config.enabled:
            return None
        
        if self.config.get_only and method.upper() != "GET":
            return None
        
        key = self._make_key(url, method, params, data, headers)
        
        async with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                
                # Check expiration
                if time.time() > entry.expires_at:
                    logger.debug(
                        f"Cache entry expired for {url}",
                        extra={"url": url, "method": method}
                    )
                    del self._cache[key]
                    if entry.content_hash in self._content_hashes:
                        del self._content_hashes[entry.content_hash]
                    self.stats["misses"] += 1
                    return None
                
                # Update access stats
                entry.access_count += 1
                entry.last_accessed = time.time()
                
                # Move to end for LRU
                if self.config.policy == CachePolicy.LRU:
                    self._cache.move_to_end(key)
                
                self.stats["hits"] += 1
                self.stats["bytes_saved"] += len(entry.response_text)
                
                logger.debug(
                    f"Cache hit for {url}",
                    extra={
                        "url": url,
                        "method": method,
                        "access_count": entry.access_count,
                        "bytes_saved": len(entry.response_text)
                    }
                )
                
                return entry
        
        self.stats["misses"] += 1
        logger.debug(f"Cache miss for {url}", extra={"url": url, "method": method})
        return None
    
    async def set(
        self,
        url: str,
        method: str,
        response_text: str,
        status_code: int,
        response_headers: Dict[str, str],
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        request_headers: Optional[Dict] = None
    ) -> bool:
        """
        Cache a response.
        
        Args:
            url: Request URL
            method: HTTP method
            response_text: Response body
            status_code: HTTP status code
            response_headers: Response headers
            params: Query parameters
            data: Request body data
            request_headers: Request headers
        
        Returns:
            True if cached successfully, False otherwise
        """
        if not self.config.enabled:
            return False
        
        if self.config.get_only and method.upper() != "GET":
            return False
        
        # Check response size
        if len(response_text) > self.config.max_response_size:
            logger.debug(
                f"Response too large to cache: {len(response_text)} bytes",
                extra={"url": url, "size": len(response_text)}
            )
            return False
        
        # Get TTL
        ttl = self._get_ttl(status_code, response_headers)
        if ttl <= 0:
            logger.debug(f"TTL is 0, not caching {url}")
            return False
        
        key = self._make_key(url, method, params, data, request_headers)
        content_hash = self._hash_content(response_text)
        now = time.time()
        
        try:
            async with self._lock:
                # Check for duplicate content (different URL, same response)
                if content_hash in self._content_hashes:
                    existing_key = self._content_hashes[content_hash]
                    if existing_key in self._cache:
                        self.stats["duplicates_avoided"] += 1
                        logger.debug(
                            f"Duplicate content detected for {url}",
                            extra={"url": url, "content_hash": content_hash}
                        )
                
                # Evict if necessary
                while len(self._cache) >= self.config.max_entries:
                    self._evict()
                
                # Create cache entry
                entry = CacheEntry(
                    response_text=response_text,
                    status_code=status_code,
                    headers=dict(response_headers),
                    created_at=now,
                    expires_at=now + ttl,
                    content_hash=content_hash
                )
                
                self._cache[key] = entry
                self._content_hashes[content_hash] = key
                
                logger.debug(
                    f"Cached response for {url}",
                    extra={
                        "url": url,
                        "method": method,
                        "status_code": status_code,
                        "ttl": ttl,
                        "size_bytes": len(response_text)
                    }
                )
                
                return True
        
        except Exception as e:
            logger.error(f"Failed to cache response for {url}: {e}", exc_info=True)
            return False
    
    def _evict(self) -> None:
        """Evict entries based on configured policy."""
        if not self._cache:
            return
        
        try:
            if self.config.policy == CachePolicy.LRU:
                # Remove oldest (first item in OrderedDict)
                oldest_key = next(iter(self._cache))
                entry = self._cache.pop(oldest_key)
                if entry.content_hash in self._content_hashes:
                    del self._content_hashes[entry.content_hash]
                self.stats["evictions"] += 1
                logger.debug(f"Evicted LRU entry: {oldest_key}")
                
            elif self.config.policy == CachePolicy.TTL:
                # Remove expired entries
                now = time.time()
                expired = [k for k, v in self._cache.items() if v.expires_at < now]
                
                if expired:
                    for key in expired:
                        entry = self._cache.pop(key)
                        if entry.content_hash in self._content_hashes:
                            del self._content_hashes[entry.content_hash]
                        self.stats["evictions"] += 1
                    logger.debug(f"Evicted {len(expired)} expired entries")
                else:
                    # No expired entries, remove oldest
                    oldest_key = next(iter(self._cache))
                    entry = self._cache.pop(oldest_key)
                    if entry.content_hash in self._content_hashes:
                        del self._content_hashes[entry.content_hash]
                    self.stats["evictions"] += 1
                    logger.debug(f"No expired entries, evicted oldest: {oldest_key}")
                    
            elif self.config.policy == CachePolicy.LFU:
                # Remove least frequently used
                min_key = min(self._cache, key=lambda k: self._cache[k].access_count)
                entry = self._cache.pop(min_key)
                if entry.content_hash in self._content_hashes:
                    del self._content_hashes[entry.content_hash]
                self.stats["evictions"] += 1
                logger.debug(
                    f"Evicted LFU entry: {min_key}",
                    extra={"access_count": entry.access_count}
                )
        
        except Exception as e:
            logger.error(f"Cache eviction failed: {e}", exc_info=True)
    
    async def wait_for_pending(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: float = 30.0
    ) -> Tuple[bool, Optional[CacheEntry]]:
        """
        Wait for a pending request to complete.
        
        This prevents duplicate in-flight requests (thundering herd problem).
        
        Args:
            url: Request URL
            method: HTTP method
            params: Query parameters
            data: Request body data
            headers: Request headers
            timeout: Maximum wait time in seconds
        
        Returns:
            Tuple of (was_pending, cached_entry)
        """
        key = self._make_key(url, method, params, data, headers)
        
        async with self._lock:
            if key in self._pending:
                event = self._pending[key]
                logger.debug(f"Waiting for pending request: {url}")
            else:
                return False, None
        
        # Wait outside lock
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            logger.debug(f"Pending request completed: {url}")
            return True, await self.get(url, method, params, data, headers)
        except asyncio.TimeoutError:
            logger.warning(
                f"Timeout waiting for pending request: {url}",
                extra={"url": url, "timeout": timeout}
            )
            return True, None
    
    async def mark_pending(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> bool:
        """
        Mark a request as pending.
        
        Args:
            url: Request URL
            method: HTTP method
            params: Query parameters
            data: Request body data
            headers: Request headers
        
        Returns:
            True if marked (no existing pending request), False otherwise
        """
        key = self._make_key(url, method, params, data, headers)
        
        async with self._lock:
            if key in self._pending:
                logger.debug(f"Request already pending: {url}")
                return False
            self._pending[key] = asyncio.Event()
            logger.debug(f"Marked request as pending: {url}")
            return True
    
    async def complete_pending(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> None:
        """
        Mark a pending request as complete.
        
        Args:
            url: Request URL
            method: HTTP method
            params: Query parameters
            data: Request body data
            headers: Request headers
        """
        key = self._make_key(url, method, params, data, headers)
        
        async with self._lock:
            if key in self._pending:
                self._pending[key].set()
                del self._pending[key]
                logger.debug(f"Completed pending request: {url}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache performance metrics
        """
        hit_rate = 0.0
        total = self.stats["hits"] + self.stats["misses"]
        if total > 0:
            hit_rate = self.stats["hits"] / total * 100
        
        return {
            **self.stats,
            "entries": len(self._cache),
            "hit_rate": f"{hit_rate:.1f}%",
            "unique_content_hashes": len(self._content_hashes),
            "pending_requests": len(self._pending),
            "bytes_saved_mb": self.stats["bytes_saved"] / (1024 * 1024),
            "policy": self.config.policy.value,
            "enabled": self.config.enabled
        }
    
    def clear(self) -> None:
        """Clear all cached entries and reset statistics."""
        entries_cleared = len(self._cache)
        pending_cleared = len(self._pending)
        
        self._cache.clear()
        self._content_hashes.clear()
        self._pending.clear()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "duplicates_avoided": 0,
            "bytes_saved": 0
        }
        
        logger.info(
            f"Cache cleared: {entries_cleared} entries, {pending_cleared} pending requests",
            extra={"entries_cleared": entries_cleared, "pending_cleared": pending_cleared}
        )


# Global cache instance
_global_cache: Optional[RequestCache] = None


def get_request_cache() -> RequestCache:
    """
    Get the global request cache instance.
    
    Returns:
        Global RequestCache instance
    """
    global _global_cache
    if _global_cache is None:
        _global_cache = RequestCache()
        logger.debug("Created global request cache instance")
    return _global_cache


def configure_cache(config: CacheConfig) -> None:
    """
    Configure the global cache.
    
    Args:
        config: New cache configuration
    """
    global _global_cache
    _global_cache = RequestCache(config)
    logger.info("Global request cache reconfigured", extra={"config": config})


def reset_cache() -> None:
    """Reset the global cache instance (mainly for testing)."""
    global _global_cache
    if _global_cache:
        _global_cache.clear()
    logger.debug("Global request cache reset")