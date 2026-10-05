import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class FamilyMemberCreateRequest(BaseModel):
    member_phone: Optional[str] = Field(None, max_length=30)
    relationship: Optional[str] = Field(None, max_length=100)
    nickname: Optional[str] = Field(None, max_length=100)
    can_view_alerts: bool = False
    can_trigger_panic: bool = False
    is_child_profile: bool = False
    content_filter_enabled: bool = False
    cyberbullying_alerts: bool = False


class FamilyMemberResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    member_user_id: Optional[uuid.UUID]
    relationship: Optional[str]
    nickname: Optional[str]
    can_view_alerts: bool
    can_trigger_panic: bool
    consent_status: str
    created_at: datetime

    class Config:
        from_attributes = True


class FamilyInvitation(BaseModel):
    """An invitation as seen by the invited person."""

    id: uuid.UUID
    inviter_name: Optional[str]
    relationship: Optional[str]
    can_view_alerts: bool
    can_trigger_panic: bool
    created_at: datetime


class FamilyDashboardMember(BaseModel):
    member_id: uuid.UUID
    nickname: Optional[str]
    relationship: Optional[str]
    consent_status: str
    alerts_visible: bool
    unread_alerts: int = 0
    critical_alerts: int = 0
    latest_alert_title: Optional[str] = None
    latest_alert_at: Optional[datetime] = None


class FamilyDashboard(BaseModel):
    members: List[FamilyDashboardMember]
    total_unread_alerts: int
    total_critical_alerts: int
    pending_invitations_sent: int
