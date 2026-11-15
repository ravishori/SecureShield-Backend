from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Any
import uuid
from datetime import datetime

from app.schemas.scam_verdict import ScamVerdict


class LinkScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def _clean_url(cls, v: str) -> str:
        v = v.strip()
        if not v or any(ord(c) < 32 for c in v):
            raise ValueError("URL must be non-empty and contain no control characters")
        if len(v) < 3:
            raise ValueError("URL is too short")
        return v


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
    # Additive and optional (X-1): the shared scam verdict. None when it could not be built; every field above is unchanged.
    verdict: Optional[ScamVerdict] = None

    class Config:
        from_attributes = True
