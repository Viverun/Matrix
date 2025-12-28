"""
AI-powered chatbot for SAST analysis results using Hugging Face II.

This module provides an intelligent chatbot interface for analyzing security
scan results and providing actionable guidance to developers.
"""
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from core.groq_client import chatbot_generate, groq_manager
from core.logger import get_logger
from config import get_settings

# Initialize structured logger
logger = get_logger(__name__)
settings = get_settings()


class SASTChatbot:
    """
    Intelligent chatbot that analyzes SAST results and provides
    specific, actionable security guidance.
    
    This chatbot uses Hugging Face II (with Hugging Face fallback) to provide
    context-aware security recommendations based on scan results.
    """
    
    # Default configuration
    DEFAULT_TEMPERATURE = 0.3
    DEFAULT_MAX_TOKENS = 2048
    REQUEST_TIMEOUT = 60.0
    MAX_CONVERSATION_HISTORY = 10
    
    def __init__(self, model: Optional[str] = None) -> None:
        """
        Initialize chatbot with Groq configuration.
        
        Args:
            model: The AI model identifier to use for chat completions.
                  Defaults to settings.groq_model_chatbot.
        """
        self.client = groq_manager
        self.model = model or settings.groq_model_chatbot
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
        
        # Try Groq AI
        response, error = await self._try_groq(messages)
        if response:
            return response
        
        # Provider failed
        if error:
            error_msg = f"AI Error: {error}"
        else:
            error_msg = "Error: AI provider is unavailable or unconfigured. Please check your Groq API key."
        logger.error(f"AI provider failed: {error}")
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
    
    async def _try_groq(self, messages: List[Dict[str, str]]) -> tuple[Optional[str], Optional[str]]:
        """
        Attempt to get a response from Groq (via chatbot key).
        Returns (content, error) tuple.
        """
        if not self.client.is_configured:
            logger.debug("Groq Client not configured, skipping")
            return None, "Groq client not configured"
        
        try:
            logger.info(f"Attempting Groq chat with model: {self.model}")
            
            response = await chatbot_generate(
                messages=messages,
                model=self.model,
                temperature=self.DEFAULT_TEMPERATURE,
                max_tokens=self.DEFAULT_MAX_TOKENS
            )
            
            content = response.get('content')
            
            if content:
                self.conversation_history.append({
                    "role": "assistant",
                    "content": content
                })
                logger.info("Groq chat request successful")
                return content, None
            
            logger.warning("Groq chat returned no content")
            return None, "AI returned empty response"
            
        except Exception as e:
            logger.error(f"Groq chat error: {str(e)}", exc_info=True)
            return None, str(e)
    
    # Hugging Face fallback removed
    
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
