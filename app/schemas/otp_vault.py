from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime


class OtpVaultCreateRequest(BaseModel):
    sender: Optional[str] = None
    raw_otp: Optional[str] = None
    encrypted_content: str
    source_app: Optional[str] = None
    received_at: Optional[datetime] = None


class OtpVaultResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    sender: Optional[str]
    raw_otp: Optional[str]
    encrypted_content: str
    source_app: Optional[str]
    is_read: bool
    is_archived: bool
    received_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True
