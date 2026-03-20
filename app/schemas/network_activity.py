from pydantic import BaseModel
from typing import Optional, List
import uuid
from datetime import datetime


class NetworkActivityLog(BaseModel):
    app_package: Optional[str] = None
    app_name: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    destination_ip: Optional[str] = None
    destination_domain: Optional[str] = None


class NetworkActivityBatchRequest(BaseModel):
    device_id: uuid.UUID
    activities: List[NetworkActivityLog]


class NetworkActivityResponse(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    app_package: Optional[str]
    app_name: Optional[str]
    bytes_sent: int
    bytes_received: int
    destination_ip: Optional[str]
    destination_domain: Optional[str]
    is_suspicious: bool
    risk_reason: Optional[str]
    logged_at: datetime

    class Config:
        from_attributes = True
