from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime


class ScamCallReportRequest(BaseModel):
    caller_number: str
    call_duration_seconds: int = 0
    detection_reason: Optional[str] = None
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
