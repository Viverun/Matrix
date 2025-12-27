"""
Hugging Face AI client for security analysis.
"""
import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from huggingface_hub import InferenceClient
from huggingface_hub.utils import HfHubHTTPError

from config import get_settings
from core.logger import get_logger
from core.scan_context import llm_cache

logger = get_logger(__name__)
settings = get_settings()

# =============================================================================
# STRUCTURED PROMPT TEMPLATES
# =============================================================================
PROMPT_TEMPLATES = {
    "sql_injection": {
        "system": "You are a database security expert. Provide precise, evidence-based SQL injection analysis. No hyperbole.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: SQL Injection
- **Test Payload**: {context}
- **Server Response**:
```
{response_data}
```

## Your Structured Analysis

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["specific quoted text from response"],
    "impact": "what attacker could achieve",
    "exploitability_conditions": "requirements for exploitation",
    "severity_justification": "why this severity",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "detailed technical explanation",
    "recommendations": ["remediation steps"]
}}"""
    },
    "xss_reflected": {
        "system": "You are a web security expert. Detect XSS with minimal false positives. Evidence required.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: Reflected Cross-Site Scripting (XSS)
- **Test Payload**: {context}
- **Server Response**:
```
{response_data}
```

## Your Structured Analysis

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["exact quoted reflection from response"],
    "impact": "specific attack outcome",
    "exploitability_conditions": "what's required for exploitation",
    "severity_justification": "why this severity",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "detailed technical explanation",
    "recommendations": ["remediation steps"]
}}"""
    },
    "default": {
        "system": "You are a cybersecurity expert. Technical precision. Zero hyperbole. Evidence required.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: {vuln_type}
- **Context**: {context}
- **Response Data**:
```
{response_data}
```

## Your Structured Analysis

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding",
    "evidence": ["quoted evidence"],
    "impact": "realistic impact",
    "exploitability_conditions": "direct vs conditional",
    "severity_justification": "reasoning",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "precise explanation",
    "recommendations": ["remediation steps"]
}}"""
    }
}


class HuggingFaceClient:
    """Client for interacting with Hugging Face Inference API."""
    
    def __init__(self) -> None:
        """Initialize the Hugging Face client."""
        api_key = settings.huggingface_api_key or os.getenv("HUGGINGFACE_API_KEY")
        self.model_id = settings.huggingface_model_id or "meta-llama/Llama-2-7b-chat-hf"
        
        if api_key:
            self.client = InferenceClient(model=self.model_id, token=api_key)
            logger.info(f"Hugging Face client initialized with model: {self.model_id}")
        else:
            self.client = None
            logger.warning("HUGGINGFACE_API_KEY not found in environment - AI features disabled")
    
    @property
    def is_configured(self) -> bool:
        """
        Check if Hugging Face is properly configured.
        
        Returns:
            True if client is configured, False otherwise
        """
        return self.client is not None
    
    def _extract_json_from_response(self, text: str) -> str:
        """
        Extract JSON content from response text that may contain markdown code blocks.
        
        Args:
            text: Raw response text
        
        Returns:
            Cleaned JSON string
        """
        # Try to extract JSON if it's wrapped in markers
        if "```json" in text:
            return text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            return text.split("```")[1].split("```")[0].strip()
        return text.strip()
    
    def _create_default_response(self, reason: str) -> Dict[str, Any]:
        """
        Create a default non-vulnerable response.
        
        Args:
            reason: Reason for the default response
        
        Returns:
            Default vulnerability analysis response
        """
        return {
            "is_vulnerable": False,
            "confidence": 0,
            "reason": reason,
            "recommendations": []
        }
    
    async def analyze_vulnerability(
        self,
        vulnerability_type: str,
        context: str,
        response_data: str
    ) -> Dict[str, Any]:
        """
        Analyze a potential vulnerability using HF Inference API.
        
        Args:
            vulnerability_type: Type of vulnerability to analyze (e.g., "sql_injection")
            context: Test payload or context information
            response_data: Server response data to analyze
        
        Returns:
            Dictionary containing vulnerability analysis with keys:
            - is_vulnerable: bool
            - confidence: int (0-100)
            - finding: str
            - evidence: List[str]
            - impact: str
            - reason: str
            - recommendations: List[str]
        """
        if not self.is_configured:
            logger.warning("Analysis requested but Hugging Face AI not configured")
            return self._create_default_response("Hugging Face AI not configured")
        
        # Check cache
        cached_result = await llm_cache.get_cached_analysis(
            vulnerability_type, context, response_data
        )
        if cached_result:
            logger.debug(f"Cache hit for {vulnerability_type} analysis")
            return cached_result
        
        vuln_key = vulnerability_type.lower().replace(" ", "_")
        template_config = PROMPT_TEMPLATES.get(vuln_key, PROMPT_TEMPLATES["default"])
        
        # Format prompt based on template type
        if vuln_key == "default" or vuln_key not in PROMPT_TEMPLATES:
            prompt_content = template_config["template"].format(
                vuln_type=vulnerability_type,
                context=context[:1500],
                response_data=response_data[:2000]
            )
        else:
            prompt_content = template_config["template"].format(
                context=context[:1500],
                response_data=response_data[:2000]
            )
        
        try:
            messages = [
                {"role": "system", "content": template_config["system"]},
                {"role": "user", "content": prompt_content}
            ]
            
            logger.info(f"Analyzing {vulnerability_type} vulnerability")
            response = await asyncio.to_thread(
                self.client.chat_completion,
                messages=messages,
                max_tokens=1000,
                temperature=0.1
            )
            
            result_text = response.choices[0].message.content
            cleaned_json = self._extract_json_from_response(result_text)
            result = json.loads(cleaned_json)
            
            # Cache the successful result
            await llm_cache.cache_analysis(vulnerability_type, context, response_data, result)
            logger.info(f"Analysis complete: vulnerable={result.get('is_vulnerable', False)}")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response for {vulnerability_type}: {e}")
            return self._create_default_response(f"Invalid JSON response: {str(e)}")
        
        except HfHubHTTPError as e:
            logger.error(f"Hugging Face API error during {vulnerability_type} analysis: {e}")
            return self._create_default_response(f"API error: {str(e)}")
        
        except Exception as e:
            logger.error(f"Unexpected error during {vulnerability_type} analysis: {e}", exc_info=True)
            return self._create_default_response(f"Analysis error: {str(e)}")

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        General chat functionality for the chatbot.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content' keys
        
        Returns:
            AI response text
        """
        if not self.is_configured:
            logger.warning("Chat requested but Hugging Face AI not configured")
            return "Hugging Face AI not configured."
        
        try:
            logger.debug(f"Processing chat with {len(messages)} messages")
            response = await asyncio.to_thread(
                self.client.chat_completion,
                messages=messages,
                max_tokens=2048,
                temperature=0.3
            )
            return response.choices[0].message.content
        
        except HfHubHTTPError as e:
            logger.error(f"Hugging Face API error during chat: {e}")
            return f"Error communicating with Hugging Face API: {str(e)}"
        
        except Exception as e:
            logger.error(f"Unexpected error during chat: {e}", exc_info=True)
            return f"Error communicating with Hugging Face: {str(e)}"

    async def generate_fix_recommendation(
        self,
        vulnerability_type: str,
        code_context: str,
        technology_stack: List[str]
    ) -> Dict[str, Any]:
        """
        Generate fix recommendations for a vulnerability.
        
        Args:
            vulnerability_type: Type of vulnerability
            code_context: Code snippet or context where vulnerability was found
            technology_stack: List of technologies in use
        
        Returns:
            Dictionary with fix recommendations including:
            - summary: str
            - steps: List[str]
            - code_example: str
            - best_practices: List[str]
        """
        if not self.is_configured:
            logger.warning("Fix recommendation requested but Hugging Face AI not configured")
            return {
                "summary": "AI not configured",
                "steps": [],
                "code_example": "",
                "best_practices": []
            }
        
        stack_str = ', '.join(technology_stack) if technology_stack else "Not specified"
        prompt = f"""You are a cybersecurity expert. Generate a fix for this vulnerability.
Vulnerability: {vulnerability_type}
Technology Stack: {stack_str}
Context: {code_context[:1500]}

Respond ONLY in valid JSON format:
{{
    "summary": "string",
    "steps": ["list of steps"],
    "code_example": "string with secure code",
    "best_practices": ["list of best practices"]
}}"""
        
        try:
            logger.info(f"Generating fix recommendation for {vulnerability_type}")
            response = await asyncio.to_thread(
                self.client.chat_completion,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000
            )
            result_text = response.choices[0].message.content
            cleaned_json = self._extract_json_from_response(result_text)
            return json.loads(cleaned_json)
        
        except (json.JSONDecodeError, HfHubHTTPError, Exception) as e:
            logger.error(f"Error generating fix recommendation: {e}")
            return {
                "summary": "Error generating fix",
                "steps": [],
                "code_example": "",
                "best_practices": []
            }

    async def explain_vulnerability(self, vulnerability_type: str, severity: str) -> str:
        """
        Generate an educational explanation of a vulnerability.
        
        Args:
            vulnerability_type: Type of vulnerability to explain
            severity: Severity level of the vulnerability
        
        Returns:
            Educational explanation text (max ~300 words)
        """
        if not self.is_configured:
            logger.warning("Explanation requested but Hugging Face AI not configured")
            return f"{vulnerability_type} explanation unavailable (AI not configured)."
        
        prompt = (
            f"Explain the {vulnerability_type} vulnerability (Severity: {severity}) "
            f"for a developer. Keep it under 300 words. Be technical but clear."
        )
        
        try:
            logger.debug(f"Generating explanation for {vulnerability_type}")
            response = await asyncio.to_thread(
                self.client.chat_completion,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500
            )
            return response.choices[0].message.content
        
        except Exception as e:
            logger.error(f"Error generating explanation for {vulnerability_type}: {e}")
            return f"Could not explain {vulnerability_type} due to an error."


# Singleton instance
hf_client = HuggingFaceClient()