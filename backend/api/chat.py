"""
API routes for the security chatbot.

Provides chat interaction with AI-powered security analysis,
with Redis-backed session persistence.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from core.chatbot import SASTChatbot
from core.chat_session import chat_session_manager
from core.logger import get_logger
from api.deps import get_current_user
from models.user import User
from models.scan import Scan
from core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = get_logger(__name__)

router = APIRouter(prefix="/chat", tags=["AI Chat"])


class ChatRequest(BaseModel):
    message: str
    scan_results: Optional[str] = None
    scan_id: Optional[int] = None


class ChatResponse(BaseModel):
    response: str
    suggested_questions: List[str]


async def _get_or_create_chatbot(user_id: str) -> SASTChatbot:
    """
    Get existing chatbot from session or create a new one.
    
    Args:
        user_id: User identifier for session lookup
        
    Returns:
        SASTChatbot instance
    """
    session_data = await chat_session_manager.get_session(user_id)
    
    chatbot = SASTChatbot()
    
    if session_data:
        # Restore conversation history
        if "conversation_history" in session_data:
            chatbot.conversation_history = session_data["conversation_history"]
        if "scan_context" in session_data:
            chatbot.scan_context = session_data["scan_context"]
        logger.debug(f"Restored chat session for user: {user_id}")
    else:
        logger.debug(f"Created new chat session for user: {user_id}")
    
    return chatbot


async def _save_chatbot_session(user_id: str, chatbot: SASTChatbot) -> None:
    """Save chatbot state to session storage."""
    session_data = {
        "conversation_history": chatbot.conversation_history,
        "scan_context": getattr(chatbot, "scan_context", None)
    }
    await chat_session_manager.save_session(user_id, session_data)


@router.post("/", response_model=ChatResponse)
async def chat_endpoint(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Handle chatbot requests for a user session.
    """
    session_id = str(current_user.id)
    logger.info(f"Chat request from user {session_id}: {request.message[:50]}...")
    
    chatbot = await _get_or_create_chatbot(session_id)
    
    # Priority 1: Explicit scan_results provided in request
    if request.scan_results:
        chatbot.set_scan_context(request.scan_results)
        logger.debug(f"Set scan context from request for user {session_id}")
    # Priority 2: scan_id provided, fetch context from database
    elif request.scan_id:
        result = await db.execute(
            select(Scan).where(Scan.id == request.scan_id, Scan.user_id == current_user.id)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            logger.warning(f"Scan {request.scan_id} not found for user {session_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        if scan.chatbot_context:
            chatbot.set_scan_context(scan.chatbot_context)
        elif scan.scan_summary:
            chatbot.set_scan_context(str(scan.scan_summary))
        logger.debug(f"Set scan context from scan {request.scan_id} for user {session_id}")
    
    # Get AI response
    response = await chatbot.chat(request.message)
    suggestions = chatbot.get_suggested_questions()
    
    # Save session state
    await _save_chatbot_session(session_id, chatbot)
    
    logger.info(f"Chat response sent to user {session_id}")
    
    return ChatResponse(
        response=response,
        suggested_questions=suggestions
    )


@router.post("/reset")
async def reset_chat_endpoint(
    current_user: User = Depends(get_current_user)
):
    """
    Reset conversation history for the current user.
    """
    session_id = str(current_user.id)
    
    await chat_session_manager.delete_session(session_id)
    logger.info(f"Chat session reset for user: {session_id}")
    
    return {"status": "success", "message": "Conversation history reset"}

