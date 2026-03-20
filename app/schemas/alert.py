from pydantic import BaseModel
from typing import Optional, List
import uuid
from datetime import datetime
from app.models.alert import AlertType, AlertSeverity


class AlertResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    device_id: Optional[uuid.UUID]
    alert_type: AlertType
    title: str
    message: str
    severity: AlertSeverity
    is_read: bool
    is_dismissed: bool
    extra_data: dict
    created_at: datetime

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AlertResponse]


class PanicAlertRequest(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    message: Optional[str] = "Emergency! I need help!"
