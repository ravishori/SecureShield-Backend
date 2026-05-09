from pydantic import BaseModel
from typing import Optional, List
import uuid
from datetime import datetime


class WifiScanRequest(BaseModel):
    device_id: Optional[uuid.UUID] = None
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    signal_strength: Optional[int] = None
    encryption_type: Optional[str] = None


class WifiScanResponse(BaseModel):
    id: uuid.UUID
    device_id: Optional[uuid.UUID]
    ssid: Optional[str]
    bssid: Optional[str]
    signal_strength: Optional[int]
    encryption_type: Optional[str]
    is_open: bool
    is_suspicious: bool
    risk_level: Optional[str]
    risk_reasons: List[str]
    scanned_at: datetime

    class Config:
        from_attributes = True
