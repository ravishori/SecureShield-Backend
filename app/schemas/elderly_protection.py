from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ElderlyConfigRequest(BaseModel):
    enabled:               bool = False
    guardian_name:         Optional[str] = Field(None, max_length=100)
    guardian_phone:        Optional[str] = Field(None, max_length=20)
    guardian_email:        Optional[str] = Field(None, max_length=255)
    block_risky_installs:  bool = True
    alert_threshold:       int  = Field(40, ge=0, le=100)
    auto_alert_guardian:   bool = True
    require_approval:      bool = False
    simplified_ui:         bool = True
    large_text:            bool = True


class ElderlyConfigResponse(BaseModel):
    id:                    uuid.UUID
    user_id:               uuid.UUID
    enabled:               bool
    guardian_name:         Optional[str]
    guardian_phone:        Optional[str]
    guardian_email:        Optional[str]
    block_risky_installs:  bool
    alert_threshold:       int
    auto_alert_guardian:   bool
    require_approval:      bool
    simplified_ui:         bool
    large_text:            bool
    updated_at:            datetime

    model_config = {"from_attributes": True}


class GuardianAlertRequest(BaseModel):
    """
    Sent by the device when a risky install is detected in elderly mode
    and auto_alert_guardian is true.  Backend delivers SMS / email.
    """
    package_name:  str
    app_name:      str
    risk_score:    int
    risk_level:    str
    risk_tags:     list[str] = Field(default_factory=list)
    clone_verdict: Optional[str] = None
