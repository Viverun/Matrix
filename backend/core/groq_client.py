"""
Groq AI client for security analysis.
Replaces the previous Gemini client.
"""
import asyncio
import os
from typing import Optional, List, Dict, Any
from groq import Groq
from config import get_settings

settings = get_settings()


class GroqClient:
    """Client for interacting with Groq AI."""
    
    def __init__(self):
        """Initialize the Groq client."""
        # Check config or env var
        api_key = settings.groq_api_key or os.getenv("GROQ_API_KEY")
        
        if api_key:
            self.client = Groq(api_key=api_key)
            self.model_name = "llama-3.3-70b-versatile" # Updated to supported model
            print("[GROQ INIT] Groq client initialized successfully", flush=True)
        else:
            self.client = None
            print("[GROQ WARNING] GROQ_API_KEY not found in environment", flush=True)
    
    @property
    def is_configured(self) -> bool:
        """Check if Groq is properly configured."""
        return self.client is not None
    
    async def analyze_vulnerability(
        self,
        vulnerability_type: str,
        context: str,
        response_data: str
    ) -> Dict[str, Any]:
        """
        Analyze a potential vulnerability using AI.
        """
        if not self.is_configured:
            return {
                "is_vulnerable": False,
                "confidence": 0,
                "reason": "Groq AI not configured",
                "recommendations": []
            }
        
        prompt = f"""You are a cybersecurity expert analyzing potential vulnerabilities.

Vulnerability Type: {vulnerability_type}
Test Context: {context}
Response Data:
```
{response_data[:2000]}
```

Analyze this response and determine:
1. Is there evidence of a {vulnerability_type} vulnerability? (true/false)
2. Confidence level (0-100)
3. Detailed explanation of your findings
4. Specific remediation recommendations

Respond ONLY in valid JSON format:
{{
    "is_vulnerable": boolean,
    "confidence": number,
    "reason": "string",
    "evidence": ["list of evidence found"],
    "recommendations": ["list of remediation steps"]
}}
"""
        
        try:
            # Run blocking call in a separate thread
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            
            import json
            result_text = response.choices[0].message.content
            print(f"[GROQ DEBUG] Prompt: {prompt[:200]}...")
            print(f"[GROQ DEBUG] Response: {result_text}")
            return json.loads(result_text)
            
        except Exception as e:
            return {
                "is_vulnerable": False,
                "confidence": 0,
                "reason": f"Analysis error: {str(e)}",
                "recommendations": []
            }
    
    async def generate_fix_recommendation(
        self,
        vulnerability_type: str,
        code_context: str,
        technology_stack: List[str]
    ) -> Dict[str, Any]:
        """
        Generate fix recommendations for a vulnerability.
        """
        if not self.is_configured:
            return {
                "summary": "AI not configured",
                "steps": [],
                "code_example": ""
            }
        
        prompt = f"""You are a cybersecurity expert. Generate a fix for this vulnerability.

Vulnerability: {vulnerability_type}
Technology Stack: {', '.join(technology_stack)}
Context:
```
{code_context[:1500]}
```

Provide:
1. A summary of the fix
2. Step-by-step remediation instructions
3. Secure code example
4. Best practices to prevent this in the future

Respond ONLY in valid JSON format:
{{
    "summary": "string",
    "steps": ["list of steps"],
    "code_example": "string with secure code",
    "best_practices": ["list of best practices"]
}}
"""
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            
            import json
            result_text = response.choices[0].message.content
            return json.loads(result_text)
            
        except Exception as e:
            return {
                "summary": f"Error generating fix: {str(e)}",
                "steps": [],
                "code_example": ""
            }
    
    async def explain_vulnerability(
        self,
        vulnerability_type: str,
        severity: str
    ) -> str:
        """
        Generate an educational explanation of a vulnerability.
        """
        if not self.is_configured:
            return f"{vulnerability_type} is a security vulnerability. Configure Groq for detailed explanations."
        
        prompt = f"""Explain the {vulnerability_type} vulnerability in simple terms for a developer.

Severity: {severity}

Include:
1. What it is
2. How attackers exploit it
3. Real-world impact
4. Simple prevention methods

Keep it educational and under 300 words.
"""
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert educator."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating explanation: {str(e)}"


# Singleton instance (keeping name for backward compatibility)
gemini_client = GroqClient()
