from pydantic import BaseModel
from typing import Optional, List
import uuid
from datetime import datetime
from app.models.app_scan import RiskLevel


class AppInfo(BaseModel):
    package_name: str
    app_name: str
    version_name: Optional[str] = None
    permissions: List[str] = []
    is_system_app: bool = False


class AppScanRequest(BaseModel):
    device_id: Optional[uuid.UUID] = None
    apps: List[AppInfo]


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
