from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from core.database import get_db
from core.logger import get_logger
from core.chatbot import SASTChatbot
from models.user import User
from models.scan import Scan
from models.vulnerability import Vulnerability
from schemas.chat import ChatRequest, ChatResponse
from api.deps import get_current_user

logger = get_logger(__name__)

router = APIRouter(prefix="/chat", tags=["Chatbot"])

# Global or session-based chatbot instance?
# For now, we'll create a new one per request or use a simple singleton
# Since it's stateless (we pass the history back or keep it in the assistant), 
# we can just initialize it on the fly.
chatbot = SASTChatbot()

async def get_scan_context(scan_id: int, user_id: int, db: AsyncSession) -> str:
    """Fetch and format scan results as a context string for the AI."""
    # Verify scan belongs to user
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        return ""
    
    # Fetch vulnerabilities
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulnerabilities = vuln_result.scalars().all()
    
    if not vulnerabilities:
        return f"Scan of {scan.target_url} completed. No vulnerabilities found."
    
    context = f"SCAN REPORT for {scan.target_url}\n"
    context += f"Total findings: {len(vulnerabilities)}\n\n"
    
    for i, v in enumerate(vulnerabilities):
        context += f"FINDING #{i+1}: {v.title}\n"
        context += f"- Type: {v.vulnerability_type.value}\n"
        context += f"- Severity: {v.severity.value}\n"
        context += f"- File: {v.file_path or 'N/A'}\n"
        context += f"- URL: {v.url}\n"
        context += f"- Description: {v.description}\n"
        if v.ai_analysis:
             context += f"- AI Analysis: {v.ai_analysis}\n"
        if v.remediation:
             context += f"- Recommendation: {v.remediation}\n"
        context += "---\n"
        
    return context

@router.post("/", response_model=ChatResponse)
async def chat_with_matrix(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Send a message to the security expert chatbot.
    If scan_id is provided, findings from that scan are used as context.
    """
    try:
        # Load context if scan_id is provided
        if request.scan_id:
            logger.info(f"Loading scan context for scan_id: {request.scan_id}")
            context = await get_scan_context(request.scan_id, current_user.id, db)
            if context:
                chatbot.set_scan_context(context)
            else:
                logger.warning(f"Scan context empty or unauthorized for scan_id: {request.scan_id}")
        
        # Call chatbot
        response_text = await chatbot.chat(request.message)
        
        return ChatResponse(
            response=response_text,
            metadata=chatbot.get_conversation_metadata(),
            suggested_questions=chatbot.get_suggested_questions()
        )
        
    except Exception as e:
        logger.error(f"Chatbot error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chatbot failed: {str(e)}"
        )

@router.post("/reset")
async def reset_chatbot(current_user: User = Depends(get_current_user)):
    """Reset the current chatbot conversation history."""
    chatbot.reset_conversation()
    return {"status": "ok", "message": "Conversation reset"}
