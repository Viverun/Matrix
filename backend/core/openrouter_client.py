"""
OpenRouter AI client for security analysis.
Used for deep SAST analysis of repository code.
Includes token bucket rate limiting to control API costs.
"""
import asyncio
import os
import httpx
import json
import time
from typing import Optional, List, Dict, Any
from collections import deque
from config import get_settings

settings = get_settings()


class TokenBucket:
    """
    Token bucket rate limiter for API calls.
    
    Implements a token bucket algorithm to limit requests per minute.
    """
    
    def __init__(self, rate: int = 10, per: float = 60.0):
        """
        Initialize token bucket.
        
        Args:
            rate: Number of tokens (requests) allowed
            per: Time period in seconds (default 60 = 1 minute)
        """
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1, bypass: bool = False) -> bool:
        """
        Acquire tokens for making a request.
        
        Args:
            tokens: Number of tokens to acquire (default 1)
            bypass: Bypass rate limiting if True
            
        Returns:
            True when tokens are acquired (may wait)
        """
        if bypass:
            return True
        
        async with self.lock:
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current
            
            # Replenish tokens based on time passed
            self.allowance += time_passed * (self.rate / self.per)
            
            if self.allowance > self.rate:
                self.allowance = self.rate
            
            if self.allowance < tokens:
                # Not enough tokens, calculate wait time
                wait_time = (tokens - self.allowance) * (self.per / self.rate)
                print(f"[RATE LIMIT] Waiting {wait_time:.1f}s for OpenRouter tokens...")
                await asyncio.sleep(wait_time)
                self.allowance = 0
            else:
                self.allowance -= tokens
            
            return True


class OpenRouterClient:
    """Client for interacting with OpenRouter AI."""
    
    def __init__(self):
        """Initialize the OpenRouter client."""
        self.api_key = settings.openrouter_api_key or os.getenv("OPENROUTER_API_KEY")
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model_name = "google/gemini-2.0-flash-exp:free" # Default to a capable model
        
        # Rate limiting: 10 requests per minute by default
        self.rate_limiter = TokenBucket(
            rate=getattr(settings, 'openrouter_rpm_limit', 10),
            per=60.0
        )
        
        # Statistics
        self.total_requests = 0
        self.throttled_requests = 0
        
        if self.api_key:
            print("[OPENROUTER INIT] OpenRouter client initialized successfully", flush=True)
            print(f"[OPENROUTER] Rate limit: {self.rate_limiter.rate} requests/minute")
        else:
            print("[OPENROUTER WARNING] OPENROUTER_API_KEY not found in environment", flush=True)
    
    @property
    def is_configured(self) -> bool:
        """Check if OpenRouter is properly configured."""
        return bool(self.api_key)
    
    async def analyze_code(
        self,
        file_path: str,
        code_content: str,
        language: str = "python",
        bypass_rate_limit: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze source code for vulnerabilities using OpenRouter.
        
        Args:
            file_path: Path to the file being analyzed
            code_content: Source code content
            language: Programming language
            bypass_rate_limit: Bypass rate limiting for critical scans
        """
        if not self.is_configured:
            return {
                "vulnerabilities": [],
                "error": "OpenRouter AI not configured"
            }
        
        # Acquire rate limit token (may wait)
        await self.rate_limiter.acquire(bypass=bypass_rate_limit)
        
        if not bypass_rate_limit:
            self.total_requests += 1
        
        prompt = f"""You are a senior security researcher and SAST tool expert.
Analyze the following source code for security vulnerabilities.

File Path: {file_path}
Language: {language}
Source Code:
```
{code_content[:8000]}
```

Analyze this code for common security issues like SQL Injection, XSS, insecure deserialization, hardcoded secrets, misconfigurations, etc.

Respond ONLY in valid JSON format with this structure:
{{
    "vulnerabilities": [
        {{
            "type": "string (e.g., sql_injection)",
            "severity": "string (critical, high, medium, low, info)",
            "title": "Short descriptive title",
            "description": "Detailed explanation of the flaw",
            "line_number": number,
            "evidence": "Snippet of vulnerable code",
            "remediation": "How to fix it",
            "confidence": number (0-100)
        }}
    ],
    "summary": "High-level summary of the file's security posture"
}}
"""
        
        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/khanj/Matrix", # Example referer
                    "X-Title": "Matrix Security"
                }
                
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert. Output valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"}
                }
                
                response = await client.post(
                    self.base_url,
                    headers=headers,
                    json=payload,
                    timeout=60.0
                )
                
                response.raise_for_status()
                result = response.json()
                
                content = result['choices'][0]['message']['content']
                print(f"[OPENROUTER] Analyzed {file_path} ({len(code_content)} chars)")
                return json.loads(content)
                
        except Exception as e:
            print(f"[OPENROUTER ERROR] Analysis failed for {file_path}: {e}")
            return {
                "vulnerabilities": [],
                "error": str(e)
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        return {
            "total_requests": self.total_requests,
            "throttled_requests": self.throttled_requests,
            "current_allowance": self.rate_limiter.allowance,
            "rate_limit": f"{self.rate_limiter.rate}/min"
        }

# Singleton instance
openrouter_client = OpenRouterClient()
