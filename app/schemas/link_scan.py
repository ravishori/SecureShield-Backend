from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime


class LinkScanRequest(BaseModel):
    url: str


class LinkScanResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    url: str
    is_phishing: bool
    is_malicious: bool
    risk_score: float
    threat_category: Optional[str]
    scan_provider: str
    scanned_at: datetime

    class Config:
        from_attributes = True
