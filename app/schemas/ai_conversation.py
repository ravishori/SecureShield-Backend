from pydantic import BaseModel
from typing import Optional, List
import uuid
from datetime import datetime
from app.models.ai_conversation import ConversationRole


class ChatRequest(BaseModel):
    session_id: Optional[uuid.UUID] = None
    message: str
    topic_category: Optional[str] = None


class ChatResponse(BaseModel):
    session_id: uuid.UUID
    reply: str
    topic_category: Optional[str]


class ConversationMessageResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    role: ConversationRole
    content: str
    topic_category: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ComplaintEmailRequest(BaseModel):
    incident_type: str
    description: str
    evidence_summary: Optional[str] = None
    suspect_info: Optional[str] = None


class ComplaintEmailResponse(BaseModel):
    subject: str
    body: str
    to_addresses: List[str]
