"""
Shared Scan Context and LLM Cache Infrastructure.

Provides:
- ScanContext: Shared data structure for inter-agent communication
- LLMCache: Redis-based caching for AI responses to reduce API costs
"""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from core.logger import get_logger

logger = get_logger(__name__)

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis package not installed - LLM caching will use memory fallback")


class AgentPhase(str, Enum):
    """Execution phases for agent dependency graph."""
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"


@dataclass
class DiscoveredCredential:
    """Credentials discovered during scanning."""
    username: str
    password: str
    source: str  # Which agent/endpoint discovered it
    endpoint: str
    confidence: float  # 0-100


@dataclass
class DatabaseInfo:
    """Database information discovered during scanning."""
    db_type: str  # MySQL, PostgreSQL, MSSQL, Oracle, etc.
    version: Optional[str] = None
    schema_info: Dict[str, Any] = field(default_factory=dict)
    discovered_by: str = ""


@dataclass
class SessionToken:
    """Session tokens discovered during scanning."""
    token_name: str
    token_value: str
    endpoint: str
    expiry: Optional[datetime] = None
    is_valid: bool = True


@dataclass
class ScanContext:
    """
    Shared context for inter-agent communication during a scan.
    
    Agents can read from and write to this context to share discoveries,
    enabling more intelligent and coordinated testing.
    """
    scan_id: int
    target_url: str
    
    # Discoveries that agents can share
    discovered_credentials: List[DiscoveredCredential] = field(default_factory=list)
    database_info: Optional[DatabaseInfo] = None
    session_tokens: List[SessionToken] = field(default_factory=list)
    discovered_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    technology_stack: List[str] = field(default_factory=list)
    
    # Security findings shared between agents
    confirmed_vulnerabilities: List[str] = field(default_factory=list)
    
    # Authentication state
    authenticated: bool = False
    auth_cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    
    # CSP and security headers
    security_headers: Dict[str, str] = field(default_factory=dict)
    csp_policy: Optional[str] = None
    
    # Metadata - UPDATED to use timezone-aware datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_credential(
        self,
        username: str,
        password: str,
        source: str,
        endpoint: str,
        confidence: float = 100.0
    ) -> None:
        """
        Add discovered credentials to the scan context.
        
        Args:
            username: Username found
            password: Password found
            source: Agent or module that discovered it
            endpoint: Endpoint where it was discovered
            confidence: Confidence level (0-100)
        """
        cred = DiscoveredCredential(
            username=username,
            password=password,
            source=source,
            endpoint=endpoint,
            confidence=confidence
        )
        self.discovered_credentials.append(cred)
        self.updated_at = datetime.now(timezone.utc)
        
        logger.info(
            f"Credential added from {source}: {username} (confidence: {confidence}%)",
            extra={"scan_id": self.scan_id, "source": source, "endpoint": endpoint}
        )
    
    def add_session_token(self, name: str, value: str, endpoint: str) -> None:
        """
        Add discovered session token.
        
        Args:
            name: Token name/identifier
            value: Token value
            endpoint: Endpoint where token was discovered
        """
        token = SessionToken(
            token_name=name,
            token_value=value,
            endpoint=endpoint
        )
        self.session_tokens.append(token)
        self.updated_at = datetime.now(timezone.utc)
        
        logger.debug(
            f"Session token added: {name}",
            extra={"scan_id": self.scan_id, "token_name": name}
        )
    
    def set_database_info(
        self,
        db_type: str,
        version: Optional[str] = None,
        discovered_by: str = ""
    ) -> None:
        """
        Set database information discovered during scanning.
        
        Args:
            db_type: Database type (MySQL, PostgreSQL, etc.)
            version: Database version if detected
            discovered_by: Agent that discovered this info
        """
        self.database_info = DatabaseInfo(
            db_type=db_type,
            version=version,
            discovered_by=discovered_by
        )
        self.updated_at = datetime.now(timezone.utc)
        
        logger.info(
            f"Database detected: {db_type} {version or 'unknown version'}",
            extra={"scan_id": self.scan_id, "db_type": db_type, "discovered_by": discovered_by}
        )
    
    def mark_authenticated(
        self,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Mark scan as authenticated with optional session data.
        
        Args:
            cookies: Authentication cookies
            headers: Authentication headers
        """
        self.authenticated = True
        if cookies:
            self.auth_cookies.update(cookies)
        if headers:
            self.auth_headers.update(headers)
        self.updated_at = datetime.now(timezone.utc)
        
        logger.info(
            "Scan marked as authenticated",
            extra={"scan_id": self.scan_id, "has_cookies": bool(cookies), "has_headers": bool(headers)}
        )
    
    def get_valid_credentials(self) -> List[DiscoveredCredential]:
        """
        Get credentials with high confidence (>=70%).
        
        Returns:
            List of high-confidence credentials
        """
        return [c for c in self.discovered_credentials if c.confidence >= 70.0]
    
    def has_database_info(self) -> bool:
        """
        Check if database information is available.
        
        Returns:
            True if database info has been discovered
        """
        return self.database_info is not None


class LLMCache:
    """
    Redis-based cache for LLM responses to reduce API costs.
    
    Caches AI analysis results using SHA-256 hashed prompts as keys.
    Supports TTL-based expiration and cache statistics.
    """
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        ttl_hours: int = 24,
        enabled: bool = True
    ) -> None:
        """
        Initialize LLM cache.
        
        Args:
            redis_url: Redis connection URL
            ttl_hours: Time to live for cached entries in hours
            enabled: Whether caching is enabled
        """
        self.redis_url = redis_url
        self.ttl_seconds = ttl_hours * 3600
        self.enabled = enabled and REDIS_AVAILABLE
        self.redis: Optional[aioredis.Redis] = None
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.errors = 0
        
        # In-memory fallback cache
        self.memory_cache: Dict[str, tuple] = {}  # {hash: (data, expiry)}
        
        if not REDIS_AVAILABLE and enabled:
            logger.warning("Falling back to in-memory cache (not persistent)")
        
        logger.info(f"LLM cache initialized (enabled: {self.enabled}, TTL: {ttl_hours}h)")
    
    async def connect(self) -> None:
        """Connect to Redis instance."""
        if not self.enabled or not REDIS_AVAILABLE:
            return
        
        try:
            self.redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis.ping()
            logger.info("Connected to Redis successfully")
        except ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            logger.warning("Falling back to in-memory cache")
            self.redis = None
        except Exception as e:
            logger.error(f"Unexpected error connecting to Redis: {e}", exc_info=True)
            self.redis = None
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            logger.info("Disconnected from Redis")
    
    def _generate_cache_key(self, prompt_parts: List[str]) -> str:
        """
        Generate cache key from prompt components.
        
        Args:
            prompt_parts: List of strings to hash (vuln_type, context, response_data, etc.)
            
        Returns:
            SHA-256 hash as hex string
        """
        combined = "|".join(str(part) for part in prompt_parts)
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    async def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached LLM response.
        
        Args:
            cache_key: Cache key (SHA-256 hash)
            
        Returns:
            Cached response dict or None if not found
        """
        if not self.enabled:
            return None
        
        try:
            # Try Redis first
            if self.redis:
                cached = await self.redis.get(f"llm_cache:{cache_key}")
                if cached:
                    self.hits += 1
                    logger.debug(
                        f"Cache hit: {cache_key[:16]}... (Hit rate: {self.hit_rate:.1f}%)"
                    )
                    return json.loads(cached)
            
            # Fallback to memory cache
            if cache_key in self.memory_cache:
                data, expiry = self.memory_cache[cache_key]
                if datetime.now(timezone.utc) < expiry:
                    self.hits += 1
                    logger.debug(f"Memory cache hit: {cache_key[:16]}...")
                    return data
                else:
                    # Expired - remove it
                    del self.memory_cache[cache_key]
            
            self.misses += 1
            return None
            
        except json.JSONDecodeError as e:
            logger.error(f"Cache get failed - invalid JSON: {e}")
            self.errors += 1
            return None
        except Exception as e:
            logger.error(f"Cache get failed: {e}", exc_info=True)
            self.errors += 1
            return None
    
    async def set(self, cache_key: str, data: Dict[str, Any]) -> None:
        """
        Store LLM response in cache.
        
        Args:
            cache_key: Cache key (SHA-256 hash)
            data: Response data to cache
        """
        if not self.enabled:
            return
        
        try:
            json_data = json.dumps(data)
            
            # Try Redis first
            if self.redis:
                await self.redis.setex(
                    f"llm_cache:{cache_key}",
                    self.ttl_seconds,
                    json_data
                )
                logger.debug(f"Cached in Redis: {cache_key[:16]}...")
            else:
                # Fallback to memory cache
                expiry = datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)
                self.memory_cache[cache_key] = (data, expiry)
                logger.debug(f"Cached in memory: {cache_key[:16]}...")
                
                # Cleanup expired entries (simple LRU)
                if len(self.memory_cache) > 1000:
                    self._cleanup_memory_cache()
                    
        except TypeError as e:
            logger.error(f"Cache set failed - data not JSON serializable: {e}")
            self.errors += 1
        except Exception as e:
            logger.error(f"Cache set failed: {e}", exc_info=True)
            self.errors += 1
    
    def _cleanup_memory_cache(self) -> None:
        """Clean up expired entries from memory cache."""
        now = datetime.now(timezone.utc)
        expired_keys = [k for k, (_, expiry) in self.memory_cache.items() if now >= expiry]
        for key in expired_keys:
            del self.memory_cache[key]
        logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    @property
    def hit_rate(self) -> float:
        """
        Calculate cache hit rate percentage.
        
        Returns:
            Hit rate as percentage (0-100)
        """
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return (self.hits / total) * 100
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache performance metrics
        """
        return {
            "enabled": self.enabled,
            "backend": "redis" if self.redis else "memory",
            "hits": self.hits,
            "misses": self.misses,
            "errors": self.errors,
            "hit_rate": f"{self.hit_rate:.1f}%",
            "memory_cache_size": len(self.memory_cache)
        }
    
    async def clear(self) -> None:
        """Clear all cached entries."""
        if self.redis:
            try:
                # Clear all llm_cache:* keys
                keys = await self.redis.keys("llm_cache:*")
                if keys:
                    await self.redis.delete(*keys)
                    logger.info(f"Cleared {len(keys)} entries from Redis")
            except Exception as e:
                logger.error(f"Failed to clear Redis cache: {e}")
        
        self.memory_cache.clear()
        logger.info("Memory cache cleared")
    
    async def get_cached_analysis(
        self,
        vulnerability_type: str,
        context: str,
        response_data: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached vulnerability analysis.
        
        Args:
            vulnerability_type: Type of vulnerability being analyzed
            context: Test context
            response_data: Response data
            
        Returns:
            Cached analysis or None if not found
        """
        # Truncate for consistent cache keys
        cache_key = self._generate_cache_key([
            vulnerability_type,
            context[:500],
            response_data[:500]
        ])
        return await self.get(cache_key)
    
    async def cache_analysis(
        self,
        vulnerability_type: str,
        context: str,
        response_data: str,
        analysis_result: Dict[str, Any]
    ) -> None:
        """
        Cache vulnerability analysis result.
        
        Args:
            vulnerability_type: Type of vulnerability analyzed
            context: Test context
            response_data: Response data
            analysis_result: AI analysis result to cache
        """
        cache_key = self._generate_cache_key([
            vulnerability_type,
            context[:500],
            response_data[:500]
        ])
        await self.set(cache_key, analysis_result)


# Global cache instance
llm_cache = LLMCache()