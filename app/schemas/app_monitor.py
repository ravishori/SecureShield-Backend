from __future__ import annotations
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
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
    client_timestamp: Optional[int] = None  # when event was observed (epoch millis)
    # New (optional, so old clients keep working): the device-generated id that makes a retry idempotent, and the time the
    # event happened (epoch millis; falls back to client_timestamp).
    client_event_id: Optional[uuid.UUID] = None
    occurred_at: Optional[int] = None


class BatchSyncRequest(BaseModel):
    """Offline-first batch upload: up to 50 events at once."""

    # Each item is validated on its own: a malformed event is REJECTED in the per-event outcomes instead of failing the batch.
    # (Structural errors - not a list, more than 50 items - are still a 422 for the whole request.)
    events: List[Union[AppEventPayload, Dict[str, Any]]] = Field(
        ...,
        max_length=50,
        json_schema_extra={"items": {"$ref": "#/components/schemas/AppEventPayload"}},
    )


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


class GuardianOutcome(BaseModel):
    """Independent of the history outcome. queued/sent/already: an alert exists for this event. skipped: not eligible.
    expired: too old to be worth sending. none: not applicable (duplicate of an event with no alert, rejected)."""

    status: str
    reason: Optional[str] = None


class EventOutcome(BaseModel):
    index: int  # position in the request, so the device can match outcomes without trusting ids
    client_event_id: Optional[uuid.UUID] = None
    status: str  # created | duplicate | rejected
    id: Optional[uuid.UUID] = None  # server id (created or duplicate)
    reason: Optional[str] = None  # rejected: invalid_payload | bad_timestamp
    fields: Optional[List[str]] = (
        None  # rejected: names of the offending fields (never their values)
    )
    guardian: Optional[GuardianOutcome] = None


class BatchSyncResponse(BaseModel):
    synced: int  # number of events CREATED by this call (unchanged meaning, for old clients)
    results: List[AppEventResponse]  # the created events (unchanged, for old clients)
    outcomes: List[EventOutcome] = []  # one per request item, in request order


class MonitorHistoryResponse(BaseModel):
    events: List[AppEventResponse]
    total: int
