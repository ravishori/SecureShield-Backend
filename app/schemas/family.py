from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime


class FamilyMemberCreateRequest(BaseModel):
    member_phone: Optional[str] = None
    relationship: Optional[str] = None
    nickname: Optional[str] = None
    can_view_alerts: bool = False
    can_trigger_panic: bool = False


class FamilyMemberResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    member_user_id: Optional[uuid.UUID]
    relationship: Optional[str]
    nickname: Optional[str]
    can_view_alerts: bool
    can_trigger_panic: bool
    created_at: datetime

    class Config:
        from_attributes = True
