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
    groq_api_key: str = ""
    huggingface_api_key_ii: str = ""
    
    # LLM Cost Optimization
    enable_llm_cache: bool = True
    llm_cache_ttl_hours: int = 24
    huggingface_ii_rpm_limit: int = 10  # Requests per minute
    groq_rpm_limit: int = 30  # Requests per minute
    huggingface_rpm_limit: int = 5 # Requests per minute
    
    # Hugging Face
    huggingface_api_key: str = ""
    huggingface_model_id: str = "Trendyol/Trendyol-Cybersecurity-LLM-v2-70B-Q4_K_M" # Default model
    
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
