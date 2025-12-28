"""
Multi-API Key Groq Manager
Isolates rate limits and costs across different services
"""
import asyncio
import os
import time
from typing import Any, Dict, List, Optional, Literal
from enum import Enum
from dataclasses import dataclass
import groq

from config import get_settings
from core.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class ModelTier(Enum):
    """Model tiers for different complexity levels."""
    FAST = "fast"
    STANDARD = "standard"
    CRITICAL = "critical"
    LARGE_CONTEXT = "large_context"
    STRUCTURED = "structured"


@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    model_id: str
    description: str
    best_for: List[str]
    speed: str
    cost_tier: str
    context_window: int
    recommended_temp: float


class GroqModels:
    """Available Groq models with characteristics."""
    LLAMA_8B_INSTANT = ModelConfig(
        model_id="llama-3.1-8b-instant",
        description="Fastest model, ideal for simple patterns",
        best_for=["quick scans", "pattern matching"],
        speed="ultra-fast",
        cost_tier="lowest",
        context_window=128000,
        recommended_temp=0.2
    )
    LLAMA_70B_VERSATILE = ModelConfig(
        model_id="llama-3.3-70b-versatile",
        description="Best balance of speed and intelligence",
        best_for=["general purpose", "logic analysis"],
        speed="fast",
        cost_tier="medium",
        context_window=128000,
        recommended_temp=0.3
    )
    LLAMA_70B_TOOL_USE = ModelConfig(
        model_id="llama-3.3-70b-tool-use",
        description="Optimized for structured outputs",
        best_for=["JSON extraction", "API calls"],
        speed="fast",
        cost_tier="medium",
        context_window=128000,
        recommended_temp=0.1
    )
    MIXTRAL_8X7B = ModelConfig(
        model_id="llama-3.3-70b-versatile", # Replaced decommissioned Mixtral
        description="Large context window model (128k)",
        best_for=["large codebases", "long documents"],
        speed="medium",
        cost_tier="medium",
        context_window=128000,
        recommended_temp=0.3
    )
    LLAMA_70B_SPECDEC = ModelConfig(
        model_id="llama-3.1-70b-specdec",
        description="Enhanced accuracy with speculative decoding",
        best_for=["critical analysis", "verification"],
        speed="fast",
        cost_tier="medium",
        context_window=8192,
        recommended_temp=0.3
    )


class ServiceModelStrategy:
    """Strategy for selecting models based on service and task."""

    @staticmethod
    def get_model(service: 'ServiceType', tier: ModelTier = ModelTier.STANDARD) -> str:
        """Get appropriate model ID for service and tier."""
        
        # Scanner Strategy
        if service == ServiceType.SECURITY_SCANNER:
            if tier == ModelTier.FAST:
                return settings.groq_model_scanner_fast
            elif tier == ModelTier.CRITICAL:
                return settings.groq_model_scanner_critical
            else:
                return settings.groq_model_scanner_primary

        # Repo Analysis Strategy
        elif service == ServiceType.REPO_ANALYSIS:
            if tier == ModelTier.LARGE_CONTEXT:
                return settings.groq_model_repo_large_files
            else:
                return settings.groq_model_repo_primary

        # Chatbot Strategy
        elif service == ServiceType.CHATBOT:
            return settings.groq_model_chatbot
            
        # Fallback Strategy
        else:
            if tier == ModelTier.FAST:
                 return "llama-3.1-8b-instant"
            return settings.groq_model_fallback


class ServiceType(Enum):
    """Different services requiring API access."""
    SECURITY_SCANNER = "scanner"  # Website vulnerability scanning
    REPO_ANALYSIS = "repo"        # GitHub/code repository analysis
    CHATBOT = "chatbot"           # User-facing conversational AI
    FALLBACK = "fallback"         # Emergency backup key


# Forward reference fix for ServiceType in strategy


@dataclass
class KeyMetrics:
    """Track usage metrics per API key."""
    service: ServiceType
    total_requests: int = 0
    failed_requests: int = 0
    rate_limit_hits: int = 0
    total_tokens_used: int = 0
    last_reset: float = 0
    daily_limit: int = 14400  # Groq's free tier limit
    
    @property
    def requests_remaining(self) -> int:
        """Estimate remaining requests today."""
        # Reset counter if it's a new day
        if time.time() - self.last_reset > 86400:  # 24 hours
            return self.daily_limit
        return max(0, self.daily_limit - self.total_requests)
    
    @property
    def usage_percentage(self) -> float:
        """Current usage as percentage of daily limit."""
        return (self.total_requests / self.daily_limit) * 100


class MultiKeyGroqManager:
    """
    Manages multiple Groq API keys for different services.
    Provides isolation, failover, and usage tracking.
    """
    
    def __init__(self) -> None:
        """Initialize manager with multiple API keys."""
        self.keys: Dict[ServiceType, str] = {
            ServiceType.SECURITY_SCANNER: settings.groq_api_key_scanner or os.getenv("GROQ_API_KEY_SCANNER") or settings.groq_api_key,
            ServiceType.REPO_ANALYSIS: settings.groq_api_key_repo or os.getenv("GROQ_API_KEY_REPO") or settings.groq_api_key,
            ServiceType.CHATBOT: settings.groq_api_key_chatbot or os.getenv("GROQ_API_KEY_CHATBOT") or settings.groq_api_key,
            ServiceType.FALLBACK: settings.groq_api_key_fallback or os.getenv("GROQ_API_KEY_FALLBACK") or settings.groq_api_key,
        }
        
        # Initialize clients
        self.clients: Dict[ServiceType, Optional[groq.AsyncGroq]] = {}
        self.metrics: Dict[ServiceType, KeyMetrics] = {}
        
        for service, api_key in self.keys.items():
            if api_key:
                try:
                    self.clients[service] = groq.AsyncGroq(api_key=api_key)
                    self.metrics[service] = KeyMetrics(service=service, last_reset=time.time())
                    logger.info(f"Initialized Groq client for {service.value}")
                except Exception as e:
                    logger.error(f"Failed to initialize {service.value} client: {e}")
                    self.clients[service] = None
            else:
                self.clients[service] = None
                logger.warning(f"No API key provided for {service.value}")
        
        # Validate at least one key is configured
        if not any(self.clients.values()):
            logger.error("No Groq API keys configured!")
            
    @property
    def is_configured(self) -> bool:
        """Check if at least one client is configured."""
        return any(self.clients.values())
    
    def get_client(self, service: ServiceType) -> Optional[groq.AsyncGroq]:
        """Get client for specific service."""
        return self.clients.get(service)
    
    def is_service_available(self, service: ServiceType) -> bool:
        """Check if service has available client and quota."""
        client = self.clients.get(service)
        if not client:
            return False
        
        metrics = self.metrics.get(service)
        if metrics and metrics.requests_remaining < 100:
            logger.warning(f"{service.value} approaching rate limit: {metrics.requests_remaining} remaining")
            return False
        
        return True
    
    def get_fallback_client(self, primary_service: ServiceType) -> Optional[groq.AsyncGroq]:
        """
        Get fallback client when primary service is unavailable.
        Priority: FALLBACK key > Other services with capacity
        """
        # Try dedicated fallback key first
        if self.clients.get(ServiceType.FALLBACK) and self.is_service_available(ServiceType.FALLBACK):
            logger.info(f"Using fallback key for {primary_service.value}")
            return self.clients[ServiceType.FALLBACK]
        
        # Try other services with remaining capacity
        for service, client in self.clients.items():
            if service != primary_service and self.is_service_available(service):
                metrics = self.metrics[service]
                if metrics.requests_remaining > 1000:  # Only use if plenty of quota
                    logger.info(f"Using {service.value} key as fallback for {primary_service.value}")
                    return client
        
        return None
    
    async def generate(
        self,
        service: ServiceType,
        prompt: str = "",
        system_prompt: str = "You are a helpful AI assistant.",
        model: Optional[str] = None,
        tier: ModelTier = ModelTier.STANDARD,
        temperature: Optional[float] = None,
        max_tokens: int = 4096,
        json_mode: bool = False,
        allow_fallback: bool = True,
        messages: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Generate completion using appropriate service key and model strategy.
        
        Args:
            service: Which service is making the request
            prompt: User prompt
            system_prompt: System context
            model: Specific Model ID (overrides strategy if provided)
            tier: Complexity tier for automatic model selection
            temperature: Sampling temperature
            max_tokens: Max output tokens
            json_mode: Force JSON output
            allow_fallback: Use fallback key if primary exhausted
            messages: Full conversation history
        """
        # 1. Determine Model
        if not model:
            model = ServiceModelStrategy.get_model(service, tier)
            
        # 2. Determine Temperature (if not override)
        if temperature is None:
            if service == ServiceType.CHATBOT:
                temperature = settings.groq_chatbot_temperature
            elif tier == ModelTier.FAST or tier == ModelTier.STRUCTURED:
                temperature = 0.1
            else:
                temperature = 0.3

        client = self.get_client(service)
        
        # Check if primary client is available
        if not client or not self.is_service_available(service):
            if allow_fallback:
                logger.warning(f"{service.value} unavailable, attempting fallback")
                client = self.get_fallback_client(service)
                if not client:
                    # If all else fails, and we have ANY client, use it as last resort if we haven't tried
                    available_clients = [c for s, c in self.clients.items() if c]
                    if available_clients:
                         client = available_clients[0]
                         service_used = [s for s, c in self.clients.items() if c == client][0]
                         logger.warning(f"Using {service_used.value} as last resort")
                    else:
                        raise Exception(f"No available API keys for {service.value}")
                else:
                     service_used = ServiceType.FALLBACK
            else:
                raise Exception(f"{service.value} API key exhausted and fallback disabled")
        else:
            service_used = service
        
        if messages is None:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        
        kwargs = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        
        try:
            start_time = time.time()
            response = await client.chat.completions.create(**kwargs)
            duration = time.time() - start_time
            
            content = response.choices[0].message.content
            
            # Update metrics
            metrics = self.metrics[service_used]
            metrics.total_requests += 1
            metrics.total_tokens_used += response.usage.total_tokens
            
            logger.info(
                f"Generation complete for {service.value}",
                extra={
                    "service": service_used.value,
                    "model": model,
                    "duration": duration,
                    "tokens": response.usage.total_tokens,
                    "requests_remaining": metrics.requests_remaining
                }
            )
            
            return {
                "content": content,
                "service_used": service_used.value,
                "metrics": {
                    "duration": duration,
                    "tokens_used": response.usage.total_tokens,
                    "requests_remaining": metrics.requests_remaining,
                    "usage_percentage": metrics.usage_percentage
                }
            }
        
        except groq.RateLimitError as e:
            metrics = self.metrics[service_used]
            metrics.rate_limit_hits += 1
            metrics.failed_requests += 1
            
            logger.error(f"Rate limit hit for {service_used.value}: {e}")
            
            # Try fallback if not already using it
            if allow_fallback and service_used != ServiceType.FALLBACK:
                logger.info(f"Retrying with fallback after rate limit")
                return await self.generate(
                    service=ServiceType.FALLBACK,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    model=model,
                    tier=tier,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    json_mode=json_mode,
                    messages=messages,
                    allow_fallback=False  # Prevent infinite recursion
                )
            
            raise
        
        except Exception as e:
            metrics = self.metrics[service_used]
            metrics.failed_requests += 1
            logger.error(f"API error for {service_used.value}: {e}")
            raise
    
    def get_usage_report(self) -> Dict[str, Any]:
        """
        Generate usage report across all services.
        Useful for monitoring and cost tracking.
        """
        report = {
            "timestamp": time.time(),
            "services": {}
        }
        
        total_requests = 0
        total_tokens = 0
        
        for service, metrics in self.metrics.items():
            if self.clients.get(service):
                service_data = {
                    "total_requests": metrics.total_requests,
                    "failed_requests": metrics.failed_requests,
                    "rate_limit_hits": metrics.rate_limit_hits,
                    "tokens_used": metrics.total_tokens_used,
                    "requests_remaining": metrics.requests_remaining,
                    "usage_percentage": round(metrics.usage_percentage, 2),
                    "status": "healthy" if metrics.usage_percentage < 80 else "warning"
                }
                
                report["services"][service.value] = service_data
                total_requests += metrics.total_requests
                total_tokens += metrics.total_tokens_used
        
        report["summary"] = {
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "estimated_cost_usd": total_tokens * 0.0000001  # Rough estimate
        }
        
        return report
    
    def reset_daily_metrics(self):
        """Reset metrics for new day (call this from cron/scheduler)."""
        for metrics in self.metrics.values():
            metrics.total_requests = 0
            metrics.failed_requests = 0
            metrics.rate_limit_hits = 0
            metrics.last_reset = time.time()
        logger.info("Daily metrics reset")


# Singleton instance
groq_manager = MultiKeyGroqManager()


def get_groq_manager() -> MultiKeyGroqManager:
    """Get singleton manager instance."""
    return groq_manager


# Convenience functions for each service
async def scanner_generate(prompt: str, **kwargs) -> Dict[str, Any]:
    """Generate using security scanner key."""
    return await groq_manager.generate(
        service=ServiceType.SECURITY_SCANNER,
        prompt=prompt,
        **kwargs
    )


async def repo_generate(prompt: str, **kwargs) -> Dict[str, Any]:
    """Generate using repository analysis key."""
    return await groq_manager.generate(
        service=ServiceType.REPO_ANALYSIS,
        prompt=prompt,
        **kwargs
    )


async def chatbot_generate(prompt: str, **kwargs) -> Dict[str, Any]:
    """Generate using chatbot key."""
    return await groq_manager.generate(
        service=ServiceType.CHATBOT,
        prompt=prompt,
        **kwargs
    )