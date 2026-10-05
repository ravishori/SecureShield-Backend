from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
import uuid
from datetime import datetime
from app.models.ai_conversation import ConversationRole


class ChatRequest(BaseModel):
    session_id: Optional[uuid.UUID] = None
    message: str = Field(..., min_length=1, max_length=4000)
    topic_category: Optional[str] = Field(None, max_length=64)
    # ISO 639-1 language code (en/hi/mr/bn/ta/te/kn/gu/ml/pa/or/ur/as).
    # When provided, the AI replies in that language.
    language: Optional[str] = Field("en", max_length=8, pattern=r"^[A-Za-z]{2,3}(-[A-Za-z]{2,4})?$")

    @field_validator("message")
    @classmethod
    def _non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must not be blank")
        return v.strip()


class ChatResponse(BaseModel):
    session_id: uuid.UUID
    reply: str
    topic_category: Optional[str]
    language: Optional[str] = "en"


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
    incident_type: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=4000)
    bank_name: Optional[str] = Field(None, max_length=200)
    amount: Optional[str] = Field(None, max_length=50)
    incident_date: Optional[str] = Field(None, max_length=50)
    evidence_summary: Optional[str] = Field(None, max_length=2000)
    suspect_info: Optional[str] = Field(None, max_length=1000)
    language: Optional[str] = Field("en", max_length=8, pattern=r"^[A-Za-z]{2,3}(-[A-Za-z]{2,4})?$")


class ComplaintEmailResponse(BaseModel):
    subject: str
    body: str
    email: str          # same as body — for Flutter compatibility
    to_addresses: List[str]
