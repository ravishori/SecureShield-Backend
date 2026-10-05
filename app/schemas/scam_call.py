from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime


class ScamCallReportRequest(BaseModel):
    caller_number: str = Field(..., min_length=1, max_length=20)
    call_duration_seconds: int = Field(0, ge=0, le=86400)
    detection_reason: Optional[str] = Field(None, max_length=1000)
    audio_features: Optional[dict] = None


class ScamCallResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    caller_number: str
    call_duration_seconds: int
    risk_score: float
    is_blocked: bool
    detection_reason: Optional[str]
    audio_features: Optional[dict]
    detected_at: datetime

    class Config:
        from_attributes = True
