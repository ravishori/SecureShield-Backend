from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime


class DeviceRegisterRequest(BaseModel):
    device_token: str
    device_name: Optional[str] = None
    platform: Optional[str] = "android"
    os_version: Optional[str] = None
    app_version: Optional[str] = None


class DeviceResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    device_token: str
    device_name: Optional[str]
    platform: Optional[str]
    os_version: Optional[str]
    app_version: Optional[str]
    last_seen: Optional[datetime]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class DeviceUpdateRequest(BaseModel):
    device_name: Optional[str] = None
    os_version: Optional[str] = None
    app_version: Optional[str] = None
