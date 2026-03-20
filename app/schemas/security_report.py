from pydantic import BaseModel
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

    class Config:
        from_attributes = True
