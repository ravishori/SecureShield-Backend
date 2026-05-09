from pydantic import BaseModel
from typing import Optional, List, Any
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
    gsb_threats: Optional[List[Any]] = None
    scanned_at: datetime

    class Config:
        from_attributes = True
