from __future__ import annotations
import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


# ── Inbound (device → server) ─────────────────────────────────────────────────

class AppEventPayload(BaseModel):
    """Single install/update/remove event sent from the device."""
    package_name:      str
    app_name:          str
    version_name:      Optional[str] = None
    event_type:        str = "installed"          # installed / updated / removed
    installer_package: Optional[str] = None
    is_unknown_source: bool = False
    is_system_app:     bool = False
    dangerous_perms:   List[str] = Field(default_factory=list)
    perm_count:        int = 0
    local_risk_score:  int = 0                    # Kotlin-computed preliminary score
    has_overlay:       bool = False
    has_accessibility: bool = False
    first_install_time: Optional[int] = None      # epoch millis
    client_timestamp:  Optional[int] = None       # when event was observed


class BatchSyncRequest(BaseModel):
    """Offline-first batch upload: up to 50 events at once."""
    events: List[AppEventPayload] = Field(..., max_length=50)


# ── Outbound (server → device) ────────────────────────────────────────────────

class AppEventResponse(BaseModel):
    id:                uuid.UUID
    package_name:      str
    app_name:          str
    event_type:        str
    server_risk_score: int
    risk_level:        str
    risk_tags:         List[str]
    clone_probability: int
    flagged_as_clone:  bool
    clone_target_pkg:  Optional[str]
    synced_at:         datetime

    model_config = {"from_attributes": True}


class BatchSyncResponse(BaseModel):
    synced:  int
    results: List[AppEventResponse]


class MonitorHistoryResponse(BaseModel):
    events: List[AppEventResponse]
    total:  int
