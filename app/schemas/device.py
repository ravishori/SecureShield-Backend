from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime


class DeviceRegisterRequest(BaseModel):
    device_token: str = Field(..., min_length=8, max_length=512)
    device_name: Optional[str] = Field(None, max_length=255)
    platform: Optional[str] = Field("android", max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    app_version: Optional[str] = Field(None, max_length=50)


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
    device_name: Optional[str] = Field(None, max_length=255)
    os_version: Optional[str] = Field(None, max_length=100)
    app_version: Optional[str] = Field(None, max_length=50)
