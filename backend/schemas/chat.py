from pydantic import BaseModel
from typing import Optional, List, Dict

class ChatRequest(BaseModel):
    message: str
    scan_id: Optional[int] = None

class ChatResponse(BaseModel):
    response: str
    metadata: Optional[Dict] = None
    suggested_questions: Optional[List[str]] = None
