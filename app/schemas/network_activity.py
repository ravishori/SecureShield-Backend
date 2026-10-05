from pydantic import BaseModel, Field
from typing import Optional, List
import uuid
from datetime import datetime


class NetworkActivityLog(BaseModel):
    app_package: Optional[str] = Field(None, max_length=255)
    app_name: Optional[str] = Field(None, max_length=255)
    bytes_sent: int = Field(0, ge=0)
    bytes_received: int = Field(0, ge=0)
    destination_ip: Optional[str] = Field(None, max_length=64)
    destination_domain: Optional[str] = Field(None, max_length=255)


class NetworkActivityBatchRequest(BaseModel):
    device_id: uuid.UUID
    activities: List[NetworkActivityLog] = Field(..., max_length=500)


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
