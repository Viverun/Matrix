"""
Application configuration settings.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "Matrix"
    debug: bool = True
    
    # LLM Cost Optimization
    enable_llm_cache: bool = True
    llm_cache_ttl_hours: int = 24
    
    # Scanner Confidence Thresholds
    scanner_confidence_threshold_high: float = 80.0
    scanner_confidence_threshold_medium: float = 50.0
    scanner_confidence_threshold_low: float = 20.0
    
    enable_audit_mode: bool = False
    
    # Groq (LPU)
    groq_api_key: str = ""  # Deprecated (legacy)
    groq_api_key_scanner: str = ""
    groq_api_key_repo: str = ""
    groq_api_key_chatbot: str = ""
    groq_api_key_fallback: str = ""
    
    # Groq Model Configuration
    # Scanner Models
    groq_model_scanner_primary: str = "llama-3.3-70b-versatile"
    groq_model_scanner_fast: str = "llama-3.1-8b-instant"
    groq_model_scanner_critical: str = "llama-3.3-70b-versatile"
    
    # Repo Analysis Models
    groq_model_repo_primary: str = "llama-3.1-8b-instant"
    groq_model_repo_large_files: str = "llama-3.1-8b-instant"
    
    # Chatbot Models
    groq_model_chatbot: str = "llama-3.3-70b-versatile"
    groq_chatbot_temperature: float = 0.7
    
    # Fallback Models
    groq_model_fallback: str = "llama-3.3-70b-versatile"
    
    # Hugging Face (Removed)

    # GitHub
    github_token: str = ""
    
    # Database - loaded from DATABASE_URL env var, falls back to PostgreSQL default
    # For SQLite (dev only): sqlite+aiosqlite:///./matrix.db
    database_url: str = "postgresql+asyncpg://matrix:matrix_secure_pass@localhost:5432/matrix"
    
    # JWT Authentication
    secret_key: str = "change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 10080  # 7 days
    
    # Redis
    redis_url: str = "redis://localhost:6379"

    # Production Deployment
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    environment: str = "development" # production or development
    
    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
