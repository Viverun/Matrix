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
    
    # AI
    # LLM Cost Optimization
    enable_llm_cache: bool = True
    llm_cache_ttl_hours: int = 24
    # LLM Cost Optimization
    enable_llm_cache: bool = True
    llm_cache_ttl_hours: int = 24
    
    # Groq (LPU)
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
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./matrix.db"
    
    # JWT Authentication
    secret_key: str = "change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 10080  # 7 days
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
