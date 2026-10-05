from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
import uuid
from datetime import datetime
from app.models.app_scan import RiskLevel


class AppInfo(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=255)
    app_name: str = Field(..., min_length=1, max_length=255)
    version_name: Optional[str] = Field(None, max_length=100)
    permissions: List[str] = Field(default_factory=list, max_length=300)
    is_system_app: bool = False

    @field_validator("permissions")
    @classmethod
    def _perm_len(cls, v):
        return [p[:200] for p in v]


class AppScanRequest(BaseModel):
    device_id: Optional[uuid.UUID] = None
    apps: List[AppInfo] = Field(..., max_length=500)


class AppScanResult(BaseModel):
    id: uuid.UUID
    device_id: Optional[uuid.UUID]
    package_name: str
    app_name: str
    version_name: Optional[str]
    risk_score: float
    risk_level: RiskLevel
    permissions: List[str]
    is_system_app: bool
    is_malicious: bool
    threat_tags: List[str]
    scanned_at: datetime

    class Config:
        from_attributes = True


class AppScanResponse(BaseModel):
    total_apps: int
    high_risk_count: int
    results: List[AppScanResult]
