"""
OpenRouter AI client for security analysis.
Used for deep SAST analysis of repository code.
"""
import asyncio
import os
import httpx
import json
from typing import Optional, List, Dict, Any
from config import get_settings

settings = get_settings()

class OpenRouterClient:
    """Client for interacting with OpenRouter AI."""
    
    def __init__(self):
        """Initialize the OpenRouter client."""
        self.api_key = settings.openrouter_api_key or os.getenv("OPENROUTER_API_KEY")
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model_name = "google/gemini-2.0-flash-exp:free" # Default to a capable model
        
        if self.api_key:
            print("[OPENROUTER INIT] OpenRouter client initialized successfully", flush=True)
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
        language: str = "python"
    ) -> Dict[str, Any]:
        """
        Analyze source code for vulnerabilities using OpenRouter.
        """
        if not self.is_configured:
            return {
                "vulnerabilities": [],
                "error": "OpenRouter AI not configured"
            }
        
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
                return json.loads(content)
                
        except Exception as e:
            print(f"[OPENROUTER ERROR] Analysis failed for {file_path}: {e}")
            return {
                "vulnerabilities": [],
                "error": str(e)
            }

# Singleton instance
openrouter_client = OpenRouterClient()
