"""
Redis-backed Chat Session Manager.

Provides persistent storage for chatbot sessions, similar to LLMCache.
Falls back to in-memory storage if Redis is unavailable.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from core.logger import get_logger

logger = get_logger(__name__)

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis package not installed - chat sessions will use memory fallback")


class ChatSessionManager:
    """
    Manages chat sessions with Redis persistence.
    
    Stores serialized chatbot state per user, enabling session persistence
    across server restarts and horizontal scaling.
    """
    
    SESSION_PREFIX = "chat_session:"
    DEFAULT_TTL_HOURS = 24
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        ttl_hours: int = DEFAULT_TTL_HOURS
    ) -> None:
        """
        Initialize session manager.
        
        Args:
            redis_url: Redis connection URL
            ttl_hours: Session expiry in hours
        """
        self.redis_url = redis_url
        self.ttl_seconds = ttl_hours * 3600
        self.redis: Optional[aioredis.Redis] = None
        
        # In-memory fallback
        self._memory_sessions: Dict[str, Dict[str, Any]] = {}
        
        logger.info(f"ChatSessionManager initialized (TTL: {ttl_hours}h)")
    
    async def connect(self) -> bool:
        """Connect to Redis. Returns True if successful."""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using in-memory sessions")
            return False
        
        try:
            self.redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis.ping()
            logger.info("Connected to Redis for chat sessions")
            return True
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis = None
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            logger.info("Disconnected from Redis")
    
    async def get_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve session data for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Session data dict or None if not found
        """
        key = f"{self.SESSION_PREFIX}{user_id}"
        
        try:
            if self.redis:
                data = await self.redis.get(key)
                if data:
                    logger.debug(f"Session retrieved from Redis: {user_id}")
                    return json.loads(data)
            
            # Fallback to memory
            if user_id in self._memory_sessions:
                session = self._memory_sessions[user_id]
                if datetime.now(timezone.utc) < session.get("expiry", datetime.max.replace(tzinfo=timezone.utc)):
                    logger.debug(f"Session retrieved from memory: {user_id}")
                    return session.get("data")
                else:
                    del self._memory_sessions[user_id]
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None
    
    async def save_session(self, user_id: str, session_data: Dict[str, Any]) -> bool:
        """
        Save session data for a user.
        
        Args:
            user_id: User identifier
            session_data: Serializable session state
            
        Returns:
            True if saved successfully
        """
        key = f"{self.SESSION_PREFIX}{user_id}"
        
        try:
            if self.redis:
                await self.redis.setex(key, self.ttl_seconds, json.dumps(session_data))
                logger.debug(f"Session saved to Redis: {user_id}")
                return True
            
            # Fallback to memory
            expiry = datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)
            self._memory_sessions[user_id] = {"data": session_data, "expiry": expiry}
            logger.debug(f"Session saved to memory: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False
    
    async def delete_session(self, user_id: str) -> bool:
        """
        Delete a user's session.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if deleted successfully
        """
        key = f"{self.SESSION_PREFIX}{user_id}"
        
        try:
            if self.redis:
                await self.redis.delete(key)
            
            if user_id in self._memory_sessions:
                del self._memory_sessions[user_id]
            
            logger.info(f"Session deleted: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session manager statistics."""
        return {
            "backend": "redis" if self.redis else "memory",
            "memory_sessions": len(self._memory_sessions),
            "ttl_hours": self.ttl_seconds // 3600
        }


# Global instance
chat_session_manager = ChatSessionManager()
