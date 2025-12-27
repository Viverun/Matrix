"""
Hugging Face II AI client for security analysis.
Used for deep SAST analysis of repository code.
Includes token bucket rate limiting to control API costs.
"""
import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional

import httpx

from config import get_settings
from core.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class HuggingFaceIIError(Exception):
    """Base exception for Hugging Face II client errors."""
    pass


class RateLimitError(HuggingFaceIIError):
    """Exception raised when rate limit is exceeded."""
    pass


class TokenBucket:
    """
    Token bucket rate limiter for API calls.
    
    Implements a token bucket algorithm to limit requests per minute.
    Ensures API costs stay under control.
    """
    
    def __init__(self, rate: int = 10, per: float = 60.0) -> None:
        """
        Initialize token bucket.
        
        Args:
            rate: Number of tokens (requests) allowed
            per: Time period in seconds (default 60 = 1 minute)
        """
        self.rate = rate
        self.per = per
        self.allowance = float(rate)
        self.last_check = time.time()
        self.lock = asyncio.Lock()
        
        logger.debug(
            f"Token bucket initialized: {rate} requests per {per}s",
            extra={"rate": rate, "period": per}
        )
    
    async def acquire(self, tokens: int = 1, bypass: bool = False) -> bool:
        """
        Acquire tokens for making a request.
        
        Args:
            tokens: Number of tokens to acquire (default 1)
            bypass: Bypass rate limiting if True
            
        Returns:
            True when tokens are acquired (may block/wait)
        """
        if bypass:
            logger.debug("Rate limit bypassed")
            return True
        
        async with self.lock:
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current
            
            # Replenish tokens based on time passed
            self.allowance += time_passed * (self.rate / self.per)
            
            # Cap allowance at rate
            if self.allowance > self.rate:
                self.allowance = self.rate
            
            if self.allowance < tokens:
                # Not enough tokens, calculate wait time
                wait_time = (tokens - self.allowance) * (self.per / self.rate)
                logger.info(
                    f"Rate limit reached, waiting {wait_time:.1f}s for tokens",
                    extra={"wait_time": wait_time, "tokens_needed": tokens}
                )
                await asyncio.sleep(wait_time)
                self.allowance = 0
            else:
                self.allowance -= tokens
                logger.debug(
                    f"Acquired {tokens} token(s), {self.allowance:.2f} remaining",
                    extra={"tokens_acquired": tokens, "remaining": self.allowance}
                )
            
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get token bucket statistics.
        
        Returns:
            Dictionary with current state
        """
        return {
            "rate": self.rate,
            "period_seconds": self.per,
            "current_allowance": self.allowance,
            "max_allowance": self.rate
        }


class HuggingFaceClientII:
    """
    Client for interacting with Hugging Face II AI API (formerly OpenRouter).
    
    Provides SAST (Static Application Security Testing) capabilities
    using AI models through Hugging Face II.
    """
    
    def __init__(self) -> None:
        """Initialize the Hugging Face II client."""
        self.api_key = settings.huggingface_api_key_ii or os.getenv("HUGGINGFACE_API_KEY_II")
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model_name = "google/gemini-2.0-flash-exp:free"  # Default model
        
        # Rate limiting: configurable requests per minute
        rpm_limit = getattr(settings, 'huggingface_ii_rpm_limit', 10)
        self.rate_limiter = TokenBucket(rate=rpm_limit, per=60.0)
        
        # Statistics
        self.total_requests = 0
        self.throttled_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        
        if self.api_key:
            logger.info(
                "Hugging Face II client initialized",
                extra={"model": self.model_name, "rpm_limit": rpm_limit}
            )
        else:
            logger.warning("HUGGINGFACE_API_KEY_II not found - SAST features disabled")
    
    @property
    def is_configured(self) -> bool:
        """
        Check if Hugging Face II is properly configured.
        
        Returns:
            True if API key is present, False otherwise
        """
        return bool(self.api_key)
    
    def _extract_json_from_response(self, text: str) -> str:
        """
        Extract JSON content from response text.
        
        Some models wrap JSON in markdown code blocks.
        
        Args:
            text: Raw response text
        
        Returns:
            Cleaned JSON string
        """
        # Try to extract JSON if wrapped in markers
        if "```json" in text:
            return text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            return text.split("```")[1].split("```")[0].strip()
        return text.strip()
    
    async def analyze_code(
        self,
        file_path: str,
        code_content: str,
        language: str = "python",
        bypass_rate_limit: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze source code for vulnerabilities using Hugging Face II AI.
        
        Args:
            file_path: Path to the file being analyzed
            code_content: Source code content
            language: Programming language (python, javascript, java, etc.)
            bypass_rate_limit: Bypass rate limiting for critical scans
        
        Returns:
            Dictionary containing:
            - vulnerabilities: List of found vulnerabilities
            - summary: High-level security summary
            - error: Error message if analysis failed (optional)
        """
        if not self.is_configured:
            logger.warning("Code analysis requested but HUGGINGFACE_API_KEY_II not configured")
            return {
                "vulnerabilities": [],
                "error": "HUGGINGFACE_API_KEY_II not configured",
                "summary": "Analysis unavailable"
            }
        
        # Acquire rate limit token (may wait)
        try:
            await self.rate_limiter.acquire(bypass=bypass_rate_limit)
        except Exception as e:
            logger.error(f"Failed to acquire rate limit token: {e}")
            raise RateLimitError(f"Rate limiting failed: {str(e)}")
        
        if not bypass_rate_limit:
            self.throttled_requests += 1
        
        self.total_requests += 1
        
        # Truncate code if too long (to stay within token limits)
        max_code_length = 8000
        truncated_code = code_content[:max_code_length]
        truncated = len(code_content) > max_code_length
        
        prompt = f"""You are a senior security researcher and SAST tool expert.
Analyze the following source code for security vulnerabilities.

File Path: {file_path}
Language: {language}
{f"Note: Code truncated to {max_code_length} characters" if truncated else ""}

Source Code:
```{language}
{truncated_code}
```

Analyze this code for common security issues including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Hardcoded Secrets (API keys, passwords)
- Path Traversal
- Command Injection
- Insecure Configurations
- Authentication/Authorization Issues
- Cryptographic Weaknesses

Respond ONLY in valid JSON format with this structure:
{{
    "vulnerabilities": [
        {{
            "type": "string (e.g., sql_injection, xss, hardcoded_secret)",
            "severity": "string (critical, high, medium, low, info)",
            "title": "Short descriptive title",
            "description": "Detailed explanation of the security flaw",
            "line_number": number or null,
            "evidence": "Snippet of vulnerable code",
            "remediation": "How to fix this vulnerability",
            "confidence": number (0-100)
        }}
    ],
    "summary": "High-level summary of the file's security posture"
}}
"""
        
        try:
            logger.info(
                f"Analyzing {file_path} with Hugging Face II",
                extra={
                    "file": file_path,
                    "language": language,
                    "code_length": len(code_content),
                    "truncated": truncated
                }
            )
            
            async with httpx.AsyncClient() as client:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/matrix-security-scanner",
                    "X-Title": "Matrix Security Scanner"
                }
                
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert. Output valid JSON only."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.1,  # Lower temperature for more consistent results
                }
                
                response = await client.post(
                    self.base_url,
                    headers=headers,
                    json=payload,
                    timeout=60.0
                )
                
                response.raise_for_status()
                result = response.json()
                
                # Extract and parse response
                content = result['choices'][0]['message']['content']
                cleaned_json = self._extract_json_from_response(content)
                analysis = json.loads(cleaned_json)
                
                self.successful_requests += 1
                
                vuln_count = len(analysis.get('vulnerabilities', []))
                logger.info(
                    f"Analysis complete for {file_path}: {vuln_count} vulnerabilities found",
                    extra={
                        "file": file_path,
                        "vulnerabilities": vuln_count,
                        "code_length": len(code_content)
                    }
                )
                
                return analysis
        
        except httpx.HTTPStatusError as e:
            self.failed_requests += 1
            logger.error(
                f"HTTP error analyzing {file_path} with Hugging Face II: {e.response.status_code}",
                extra={"file": file_path, "status_code": e.response.status_code}
            )
            return {
                "vulnerabilities": [],
                "error": f"HTTP {e.response.status_code}: {str(e)}",
                "summary": "Analysis failed due to API error"
            }
        
        except json.JSONDecodeError as e:
            self.failed_requests += 1
            logger.error(
                f"Failed to parse JSON response for {file_path} from Hugging Face II: {e}",
                extra={"file": file_path}
            )
            return {
                "vulnerabilities": [],
                "error": f"Invalid JSON response: {str(e)}",
                "summary": "Analysis failed due to invalid response format"
            }
        
        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"Analysis timeout for {file_path} with Hugging Face II")
            return {
                "vulnerabilities": [],
                "error": "Analysis timed out after 60 seconds",
                "summary": "Analysis timed out"
            }
        
        except Exception as e:
            self.failed_requests += 1
            logger.error(
                f"Unexpected error analyzing {file_path} with Hugging Face II: {e}",
                exc_info=True,
                extra={"file": file_path}
            )
            return {
                "vulnerabilities": [],
                "error": str(e),
                "summary": "Analysis failed due to unexpected error"
            }
    
    async def analyze_multiple_files(
        self,
        files: List[Dict[str, str]],
        max_concurrent: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple files concurrently with controlled parallelism.
        
        Args:
            files: List of dicts with 'path', 'content', and 'language' keys
            max_concurrent: Maximum number of concurrent analyses
        
        Returns:
            List of analysis results
        """
        logger.info(
            f"Starting batch analysis of {len(files)} files with Hugging Face II",
            extra={"file_count": len(files), "max_concurrent": max_concurrent}
        )
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_with_semaphore(file_info: Dict[str, str]) -> Dict[str, Any]:
            async with semaphore:
                result = await self.analyze_code(
                    file_path=file_info['path'],
                    code_content=file_info['content'],
                    language=file_info.get('language', 'python')
                )
                result['file_path'] = file_info['path']
                return result
        
        tasks = [analyze_with_semaphore(f) for f in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to error dicts
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch analysis failed for {files[i]['path']}: {result}")
                processed_results.append({
                    "file_path": files[i]['path'],
                    "vulnerabilities": [],
                    "error": str(result),
                    "summary": "Analysis failed"
                })
            else:
                processed_results.append(result)
        
        logger.info(
            f"Batch analysis complete: {len(processed_results)} files processed",
            extra={"total_files": len(files), "successful": len(processed_results)}
        )
        
        return processed_results
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get client statistics including rate limiting info.
        
        Returns:
            Dictionary with statistics
        """
        rate_limiter_stats = self.rate_limiter.get_stats()
        
        success_rate = 0.0
        if self.total_requests > 0:
            success_rate = (self.successful_requests / self.total_requests) * 100
        
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "throttled_requests": self.throttled_requests,
            "success_rate": f"{success_rate:.1f}%",
            "rate_limiter": rate_limiter_stats,
            "model": self.model_name,
            "configured": self.is_configured
        }
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.throttled_requests = 0
        logger.info("Hugging Face II client statistics reset")


# Singleton instance
hf_client_ii = HuggingFaceClientII()


def get_hf_client_ii() -> HuggingFaceClientII:
    """
    Get the global Hugging Face II client instance.
    
    Returns:
        Global HuggingFaceClientII instance
    """
    return hf_client_ii
