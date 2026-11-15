from pydantic import BaseModel, computed_field
from typing import List, Optional

from app.schemas.scam_verdict import ScamVerdict
from app.services.scam_verdict_adapters import from_daily_report, safe_verdict
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

    @computed_field
    @property
    def verdict(self) -> Optional[ScamVerdict]:
        """Additive, API-only aggregate verdict (X-1). Evidence is the day's recorded ALERTS only; scan activity is never
        risk evidence (it only separates "nothing was checked" from "checks ran, no alert"). Unchanged: every field above."""
        return safe_verdict(
            from_daily_report,
            threats_detected=self.threats_detected,
            apps_scanned=self.apps_scanned,
            links_scanned=self.links_scanned,
            calls_analyzed=self.calls_analyzed,
        )

    class Config:
        from_attributes = True
