"""
AI-powered chatbot for SAST analysis results using Hugging Face II.

This module provides an intelligent chatbot interface for analyzing security
scan results and providing actionable guidance to developers.
"""
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from core.hugging_face_client import hf_client_ii
from core.logger import get_logger

# Initialize structured logger
logger = get_logger(__name__)


class SASTChatbot:
    """
    Intelligent chatbot that analyzes SAST results and provides
    specific, actionable security guidance.
    
    This chatbot uses Hugging Face II (with Hugging Face fallback) to provide
    context-aware security recommendations based on scan results.
    """
    
    # Default configuration
    DEFAULT_MODEL = "anthropic/claude-3.5-sonnet"
    DEFAULT_TEMPERATURE = 0.3
    DEFAULT_MAX_TOKENS = 2048
    REQUEST_TIMEOUT = 60.0
    MAX_CONVERSATION_HISTORY = 10
    
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        """
        Initialize chatbot with Hugging Face II configuration.
        
        Args:
            model: The AI model identifier to use for chat completions.
                  Defaults to Trendyol/Trendyol-Cybersecurity-LLM-v2-70B-Q4_K_ via Hugging Face II.
        """
        self.client = hf_client_ii
        self.model = model
        self.conversation_history: List[Dict[str, str]] = []
        self.scan_context: str = ""
        self.system_prompt: str = ""
        logger.info(f"SASTChatbot initialized with model: {model}")
    
    def set_scan_context(self, scan_results: str) -> None:
        """
        Load scan results into chatbot context and reset conversation.
        
        This method prepares the chatbot with security scan results and
        generates an appropriate system prompt for context-aware responses.
        
        Args:
            scan_results: The complete SAST scan results to provide as context.
        """
        self.scan_context = scan_results
        self.conversation_history = []
        
        # Generate system prompt with scan context
        self.system_prompt = self._generate_system_prompt(scan_results)
        logger.info("Scan context loaded. Conversation history reset.")
    
    def _generate_system_prompt(self, scan_results: str) -> str:
        """
        Generate the system prompt with embedded scan results.
        
        Args:
            scan_results: The scan results to embed in the system prompt.
            
        Returns:
            A formatted system prompt string for the AI model.
        """
        return f"""You are a senior security engineer helping a developer fix vulnerabilities in their codebase.

You have just completed a comprehensive SAST (Static Application Security Testing) scan of their GitHub repository.

SCAN CONTEXT:
{scan_results}

YOUR ROLE:
- Be direct, specific, and actionable
- Reference actual file paths, line numbers, and code from the scan results
- Explain WHY vulnerabilities are dangerous with real exploit scenarios
- Provide copy-paste ready fixes with code examples
- Prioritize based on exploitability, not just severity labels
- When showing attack payloads, format them as code blocks
- Be encouraging but realistic about security risks

RESPONSE STYLE:
- Use markdown formatting for code, commands, and structure
- Keep explanations concise but complete
- Use real examples from their codebase
- Suggest prioritization when appropriate
- Offer to generate test cases, PRs, or detailed guides

NEVER:
- Give generic advice like "use parameterized queries" without showing exactly how in their code
- List issues without explaining the actual risk
- Provide recommendations without referencing their specific findings
- Apologize excessively - focus on solutions

The developer trusts you to guide them to a more secure codebase. Be their security mentor.
"""

    async def chat(self, user_message: str) -> str:
        """
        Process user message and return AI response with automatic fallback.
        
        This method attempts to use Hugging Face II first, then falls back to
        Hugging Face (original) if Hugging Face II is unavailable or unconfigured.
        
        Args:
            user_message: The user's question or request about the scan results.
            
        Returns:
            The AI-generated response to the user's message.
            
        Raises:
            ValueError: If no scan results have been loaded via set_scan_context().
        """
        if not self.scan_context:
            error_msg = "No scan results loaded. Please run a repository scan first."
            logger.warning("Chat attempted without scan context")
            return error_msg
        
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        logger.debug(f"User message added to history. Total messages: {len(self.conversation_history)}")
        
        # Build messages with recent history
        messages = self._build_messages()
        
        # Try Hugging Face II first, then fallback to Hugging Face
        response = await self._try_hf_ii(messages)
        if response:
            return response
            
        response = await self._try_huggingface(messages)
        if response:
            return response
        
        # Both providers failed
        error_msg = "Error: Both Hugging Face II and Hugging Face AI providers are unavailable or unconfigured."
        logger.error("All AI providers failed")
        return error_msg
    
    def _build_messages(self) -> List[Dict[str, str]]:
        """
        Build the message list for the AI API call.
        
        Returns:
            A list containing the system prompt and recent conversation history.
        """
        messages = [{"role": "system", "content": self.system_prompt}]
        # Include only recent conversation history to stay within token limits
        messages.extend(self.conversation_history[-self.MAX_CONVERSATION_HISTORY:])
        return messages
    
    async def _try_hf_ii(self, messages: List[Dict[str, str]]) -> Optional[str]:
        """
        Attempt to get a response from Hugging Face II.
        
        Args:
            messages: The message history to send to the API.
            
        Returns:
            The AI response if successful, None otherwise.
        """
        if not self.client.is_configured:
            logger.debug("Hugging Face II not configured, skipping")
            return None
        
        try:
            logger.info(f"Attempting Hugging Face II request with model: {self.model}")
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.client.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.client.api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://matrix-security.app",
                        "X-Title": "Matrix AI Security"
                    },
                    json={
                        "model": self.model,
                        "messages": messages,
                        "temperature": self.DEFAULT_TEMPERATURE,
                        "max_tokens": self.DEFAULT_MAX_TOKENS
                    },
                    timeout=self.REQUEST_TIMEOUT
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = data['choices'][0]['message']['content']
                    
                    self.conversation_history.append({
                        "role": "assistant",
                        "content": content
                    })
                    logger.info("Hugging Face II request successful")
                    return content
                
                # Handle specific error cases
                if response.status_code == 402:
                    logger.warning("Hugging Face II payment required (402). Triggering fallback.")
                elif response.status_code == 429:
                    logger.warning("Hugging Face II rate limit exceeded (429). Triggering fallback.")
                else:
                    logger.warning(f"Hugging Face II request failed with status: {response.status_code}")
                
                return None
                
        except httpx.TimeoutException:
            logger.error(f"Hugging Face II request timed out after {self.REQUEST_TIMEOUT}s")
            return None
        except httpx.RequestError as e:
            logger.error(f"Hugging Face II request error: {str(e)}")
            return None
        except (KeyError, ValueError) as e:
            logger.error(f"Hugging Face II response parsing error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected Hugging Face II error: {str(e)}", exc_info=True)
            return None
    
    async def _try_huggingface(self, messages: List[Dict[str, str]]) -> Optional[str]:
        """
        Attempt to get a response from Hugging Face (fallback provider).
        
        Args:
            messages: The message history to send to the API.
            
        Returns:
            The AI response if successful, None otherwise.
        """
        logger.info("Attempting Hugging Face fallback")
        
        try:
            from core import hf_client
            
            if not hf_client.is_configured:
                logger.warning("Hugging Face client not configured")
                return None
            
            content = await hf_client.chat(messages)
            
            self.conversation_history.append({
                "role": "assistant",
                "content": content
            })
            logger.info("Hugging Face request successful")
            return content
            
        except ImportError:
            logger.error("Hugging Face client module not found")
            return None
        except Exception as e:
            logger.error(f"Hugging Face error: {str(e)}", exc_info=True)
            return None
    
    def reset_conversation(self) -> None:
        """
        Reset conversation history while keeping scan context.
        
        This is useful for starting a fresh conversation about the same
        scan results without reloading the context.
        """
        history_count = len(self.conversation_history)
        self.conversation_history = []
        logger.info(f"Conversation reset. Cleared {history_count} messages.")
    
    def get_conversation_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about the current conversation state.
        
        Returns:
            A dictionary containing conversation statistics and state.
        """
        return {
            "message_count": len(self.conversation_history),
            "has_scan_context": bool(self.scan_context),
            "model": self.model,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def get_suggested_questions(self) -> List[str]:
        """
        Generate context-aware suggested questions based on scan results.
        
        This method analyzes the scan context to provide relevant question
        suggestions to help users get started with the chatbot.
        
        Returns:
            A list of up to 5 suggested questions tailored to the scan results.
        """
        if not self.scan_context:
            return [
                "What are the most critical vulnerabilities?",
                "How do I fix the exposed secrets?",
                "Show me exploit scenarios"
            ]
        
        suggestions = []
        context_lower = self.scan_context.lower()
        
        # Analyze scan context for specific vulnerability types
        if 'critical' in context_lower:
            suggestions.append("What are the critical vulnerabilities and how do I fix them?")
        
        if any(keyword in context_lower for keyword in ['secret', 'credential', 'password', 'api key']):
            suggestions.append("How do I rotate and clean up the exposed secrets?")
        
        if 'sql' in context_lower or 'injection' in context_lower:
            suggestions.append("Show me the SQL injection vulnerabilities and attack examples")
        
        if 'xss' in context_lower or 'cross-site' in context_lower:
            suggestions.append("How do I prevent the XSS vulnerabilities?")
        
        if 'csrf' in context_lower:
            suggestions.append("Explain the CSRF vulnerabilities and how to fix them")
        
        if 'path traversal' in context_lower or 'directory traversal' in context_lower:
            suggestions.append("What are the path traversal risks in my code?")
        
        # Add generic helpful questions
        suggestions.extend([
            "Prioritize my security roadmap",
            "Generate a fix plan for the top issues",
            "Show me code examples for the findings"
        ])
        
        # Return unique suggestions, maximum 5
        seen = set()
        unique_suggestions = []
        for suggestion in suggestions:
            if suggestion not in seen:
                seen.add(suggestion)
                unique_suggestions.append(suggestion)
                if len(unique_suggestions) >= 5:
                    break
        
        logger.debug(f"Generated {len(unique_suggestions)} suggested questions")
        return unique_suggestions
