"""Core utilities and shared components."""
from .database import get_db, engine, Base
from .security import create_access_token, verify_password, get_password_hash
# from .hf_client import hf_client, HuggingFaceClient
from .groq_client import (
    groq_manager, 
    MultiKeyGroqManager,
    scanner_generate,
    repo_generate,
    chatbot_generate,
    ServiceType
)
from .rate_limiter import (
    AdaptiveRateLimiter,
    RateLimiterConfig,
    get_rate_limiter,
    configure_rate_limiter
)
from .request_cache import (
    RequestCache,
    CacheConfig,
    CachePolicy,
    get_request_cache,
    configure_cache
)

__all__ = [
    "get_db",
    "engine", 
    "Base",
    "create_access_token",
    "verify_password",
    "get_password_hash",
    # "hf_client", 
    # "HuggingFaceClient",
    "groq_manager",
    "MultiKeyGroqManager",
    "scanner_generate",
    "repo_generate",
    "chatbot_generate",
    "AdaptiveRateLimiter",
    "RateLimiterConfig",
    "get_rate_limiter",
    "configure_rate_limiter",
    "RequestCache",
    "CacheConfig",
    "CachePolicy",
    "get_request_cache",
    "configure_cache",
]
