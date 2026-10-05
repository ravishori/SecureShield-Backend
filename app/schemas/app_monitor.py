from __future__ import annotations
import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


# ── Inbound (device → server) ─────────────────────────────────────────────────


class AppEventPayload(BaseModel):
    """Single install/update/remove event sent from the device."""

    package_name: str = Field(..., min_length=1, max_length=255)
    app_name: str = Field(..., min_length=1, max_length=255)
    version_name: Optional[str] = Field(None, max_length=100)
    event_type: str = Field("installed", pattern=r"^(installed|updated|removed)$")
    installer_package: Optional[str] = Field(None, max_length=255)
    is_unknown_source: bool = False
    is_system_app: bool = False
    dangerous_perms: List[str] = Field(default_factory=list, max_length=300)
    perm_count: int = Field(0, ge=0, le=1000)
    local_risk_score: int = Field(0, ge=0, le=100)  # Kotlin-computed preliminary score
    has_overlay: bool = False
    has_accessibility: bool = False
    first_install_time: Optional[int] = None  # epoch millis
    client_timestamp: Optional[int] = None  # when event was observed


class BatchSyncRequest(BaseModel):
    """Offline-first batch upload: up to 50 events at once."""

    events: List[AppEventPayload] = Field(..., max_length=50)


# ── Outbound (server → device) ────────────────────────────────────────────────


class AppEventResponse(BaseModel):
    id: uuid.UUID
    package_name: str
    app_name: str
    event_type: str
    server_risk_score: int
    risk_level: str
    risk_tags: List[str]
    clone_probability: int
    flagged_as_clone: bool
    clone_target_pkg: Optional[str]
    synced_at: datetime

    model_config = {"from_attributes": True}


class BatchSyncResponse(BaseModel):
    synced: int
    results: List[AppEventResponse]


class MonitorHistoryResponse(BaseModel):
    events: List[AppEventResponse]
    total: int
