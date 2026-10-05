from __future__ import annotations
import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class CloneScanRequest(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=255)
    app_name: str = Field(..., min_length=1, max_length=255)
    cert_hash: Optional[str] = Field(
        None, max_length=200
    )  # SHA-256 of signing cert, colon-separated
    icon_phash: Optional[str] = Field(
        None, max_length=200
    )  # perceptual hash hex string (future)


class CloneScanResponse(BaseModel):
    id: uuid.UUID
    package_name: str
    app_name: str
    target_package: Optional[str]
    target_name: Optional[str]
    name_similarity: int  # 0-100
    package_similarity: int  # 0-100
    overall_score: int  # 0-100
    verdict: str  # safe / suspicious / likely_clone / confirmed_clone
    signals: List[str]
    action_recommended: str  # none / warn / block / uninstall
    created_at: datetime

    model_config = {"from_attributes": True}


class CloneHistoryResponse(BaseModel):
    reports: List[CloneScanResponse]
    total: int


class CloneFeedbackRequest(BaseModel):
    """User confirms or dismisses a clone finding."""

    report_id: uuid.UUID
    user_confirmed: bool  # True = user agrees it's fake
    action_taken: Optional[str] = Field(
        None, max_length=50
    )  # uninstalled / ignored / reported
