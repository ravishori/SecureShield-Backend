from pydantic import BaseModel, computed_field
from typing import List
import uuid
from datetime import datetime, date


class SecurityReportResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    report_date: date
    threats_detected: int
    apps_scanned: int
    links_scanned: int
    calls_analyzed: int
    overall_risk_score: float
    top_threats: List[dict]
    recommendations: List[str]
    created_at: datetime

    @computed_field
    @property
    def security_score(self) -> int:
        """0-100, higher is safer (the inverse of the stored risk score)."""
        return max(0, min(100, round(100 - self.overall_risk_score)))

    @computed_field
    @property
    def risk_level(self) -> str:
        r = self.overall_risk_score
        return (
            "low"
            if r < 25
            else "moderate"
            if r < 50
            else "high"
            if r < 75
            else "critical"
        )

    class Config:
        from_attributes = True
