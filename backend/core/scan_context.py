"""
Shared Scan Context and LLM Cache Infrastructure.

Provides:
- ScanContext: Shared data structure for inter-agent communication
- LLMCache: Redis-based caching for AI responses to reduce API costs
"""
import hashlib
import json
import asyncio
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("[CACHE WARNING] redis package not installed. LLM caching disabled.")


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
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_credential(self, username: str, password: str, source: str, endpoint: str, confidence: float = 100.0):
        """Add discovered credentials."""
        cred = DiscoveredCredential(
            username=username,
            password=password,
            source=source,
            endpoint=endpoint,
            confidence=confidence
        )
        self.discovered_credentials.append(cred)
        self.updated_at = datetime.utcnow()
    
    def add_session_token(self, name: str, value: str, endpoint: str):
        """Add discovered session token."""
        token = SessionToken(
            token_name=name,
            token_value=value,
            endpoint=endpoint
        )
        self.session_tokens.append(token)
        self.updated_at = datetime.utcnow()
    
    def set_database_info(self, db_type: str, version: Optional[str] = None, discovered_by: str = ""):
        """Set database information."""
        self.database_info = DatabaseInfo(
            db_type=db_type,
            version=version,
            discovered_by=discovered_by
        )
        self.updated_at = datetime.utcnow()
    
    def mark_authenticated(self, cookies: Dict[str, str] = None, headers: Dict[str, str] = None):
        """Mark scan as authenticated."""
        self.authenticated = True
        if cookies:
            self.auth_cookies.update(cookies)
        if headers:
            self.auth_headers.update(headers)
        self.updated_at = datetime.utcnow()
    
    def get_valid_credentials(self) -> List[DiscoveredCredential]:
        """Get credentials with high confidence."""
        return [c for c in self.discovered_credentials if c.confidence >= 70.0]
    
    def has_database_info(self) -> bool:
        """Check if database info is available."""
        return self.database_info is not None


class LLMCache:
    """
    Redis-based cache for LLM responses to reduce API costs.
    
    Caches AI analysis results using SHA-256 hashed prompts as keys.
    Supports TTL-based expiration and cache statistics.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", ttl_hours: int = 24, enabled: bool = True):
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
            print("[CACHE WARNING] Falling back to in-memory cache (not persistent)")
    
    async def connect(self):
        """Connect to Redis."""
        if not self.enabled or not REDIS_AVAILABLE:
            return
        
        try:
            self.redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis.ping()
            print("[CACHE] Connected to Redis successfully")
        except Exception as e:
            print(f"[CACHE ERROR] Failed to connect to Redis: {e}")
            print("[CACHE] Falling back to in-memory cache")
            self.redis = None
    
    async def disconnect(self):
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
    
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
                    print(f"[CACHE HIT] Key: {cache_key[:16]}... (Hit rate: {self.hit_rate:.1f}%)")
                    return json.loads(cached)
            
            # Fallback to memory cache
            if cache_key in self.memory_cache:
                data, expiry = self.memory_cache[cache_key]
                if datetime.utcnow() < expiry:
                    self.hits += 1
                    print(f"[CACHE HIT] Memory cache key: {cache_key[:16]}...")
                    return data
                else:
                    # Expired
                    del self.memory_cache[cache_key]
            
            self.misses += 1
            return None
            
        except Exception as e:
            print(f"[CACHE ERROR] Get failed: {e}")
            self.errors += 1
            return None
    
    async def set(self, cache_key: str, data: Dict[str, Any]):
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
                print(f"[CACHE SET] Stored in Redis: {cache_key[:16]}...")
            else:
                # Fallback to memory cache
                expiry = datetime.utcnow() + timedelta(seconds=self.ttl_seconds)
                self.memory_cache[cache_key] = (data, expiry)
                print(f"[CACHE SET] Stored in memory: {cache_key[:16]}...")
                
                # Cleanup expired entries (simple LRU)
                if len(self.memory_cache) > 1000:
                    self._cleanup_memory_cache()
                    
        except Exception as e:
            print(f"[CACHE ERROR] Set failed: {e}")
            self.errors += 1
    
    def _cleanup_memory_cache(self):
        """Clean up expired entries from memory cache."""
        now = datetime.utcnow()
        expired_keys = [k for k, (_, expiry) in self.memory_cache.items() if now >= expiry]
        for key in expired_keys:
            del self.memory_cache[key]
        print(f"[CACHE] Cleaned up {len(expired_keys)} expired entries")
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate percentage."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return (self.hits / total) * 100
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "enabled": self.enabled,
            "backend": "redis" if self.redis else "memory",
            "hits": self.hits,
            "misses": self.misses,
            "errors": self.errors,
            "hit_rate": f"{self.hit_rate:.1f}%",
            "memory_cache_size": len(self.memory_cache)
        }
    
    async def clear(self):
        """Clear all cached entries."""
        if self.redis:
            # Clear all llm_cache:* keys
            keys = await self.redis.keys("llm_cache:*")
            if keys:
                await self.redis.delete(*keys)
                print(f"[CACHE] Cleared {len(keys)} entries from Redis")
        
        self.memory_cache.clear()
        print("[CACHE] Cleared memory cache")
    
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
            Cached analysis or None
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
    ):
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
