from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime


class EmergencyContactCreate(BaseModel):
    name: str
    relationship: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None


class EmergencyContactResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    relationship: Optional[str]
    phone: Optional[str]
    email: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
