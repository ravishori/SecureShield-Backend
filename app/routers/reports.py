from datetime import datetime, date, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.security_report import SecurityReport
from app.models.alert import Alert
from app.models.app_scan import AppScan
from app.models.link_scan import LinkScan
from app.models.scam_call import ScamCall
from app.models.behavior_event import BehaviorEvent, BehaviorEventType
from app.schemas.security_report import SecurityReportResponse
from app.routers.auth import get_current_user
from app.services.ai_service import generate_ai_security_tips

router = APIRouter(prefix="/reports", tags=["reports"])


async def generate_daily_report(user_id, report_date: date, db: AsyncSession) -> SecurityReport:
    start = datetime.combine(report_date, datetime.min.time())
    end = start + timedelta(days=1)

    # Count threats
    threats_result = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.user_id == user_id,
            Alert.created_at >= start,
            Alert.created_at < end,
        )
    )
    threats_detected = threats_result.scalar() or 0

    apps_result = await db.execute(
        select(func.count()).select_from(AppScan).where(
            AppScan.scanned_at >= start,
            AppScan.scanned_at < end,
        )
    )
    apps_scanned = apps_result.scalar() or 0

    links_result = await db.execute(
        select(func.count()).select_from(LinkScan).where(
            LinkScan.user_id == user_id,
            LinkScan.scanned_at >= start,
            LinkScan.scanned_at < end,
        )
    )
    links_scanned = links_result.scalar() or 0

    calls_result = await db.execute(
        select(func.count()).select_from(ScamCall).where(
            ScamCall.user_id == user_id,
            ScamCall.detected_at >= start,
            ScamCall.detected_at < end,
        )
    )
    calls_analyzed = calls_result.scalar() or 0

    # Risky behavior events today
    behavior_result = await db.execute(
        select(BehaviorEvent).where(
            BehaviorEvent.user_id == user_id,
            BehaviorEvent.occurred_at >= start,
            BehaviorEvent.occurred_at < end,
        )
    )
    behavior_events = behavior_result.scalars().all()
    risky_behaviors = [e.event_type.value for e in behavior_events]
    behavior_risk = sum(e.risk_contribution for e in behavior_events)

    # Alert types breakdown
    alerts_result = await db.execute(
        select(Alert).where(
            Alert.user_id == user_id,
            Alert.created_at >= start,
            Alert.created_at < end,
        )
    )
    alerts = alerts_result.scalars().all()
    top_threat_types = list({a.alert_type.value for a in alerts})

    # Calculate overall risk score
    overall_risk = min(
        (threats_detected * 10 + apps_scanned * 0.5 + links_scanned * 2 + behavior_risk),
        100.0
    )

    # Generate AI-powered personalized tips
    ai_tips = await generate_ai_security_tips(
        threats_detected=threats_detected,
        risk_score=overall_risk,
        top_threat_types=top_threat_types,
        risky_behaviors=risky_behaviors,
    )

    top_threats = []
    if threats_detected > 0:
        top_threats.append({"type": "general", "count": threats_detected})
    if links_scanned > 0:
        top_threats.append({"type": "phishing_links", "count": links_scanned})
    if calls_analyzed > 0:
        top_threats.append({"type": "scam_calls", "count": calls_analyzed})
    if risky_behaviors:
        top_threats.append({"type": "risky_behaviors", "count": len(risky_behaviors), "details": risky_behaviors[:5]})

    report = SecurityReport(
        user_id=user_id,
        report_date=report_date,
        threats_detected=threats_detected,
        apps_scanned=apps_scanned,
        links_scanned=links_scanned,
        calls_analyzed=calls_analyzed,
        overall_risk_score=overall_risk,
        top_threats=top_threats,
        recommendations=ai_tips,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/daily", response_model=SecurityReportResponse)
async def get_daily_report(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    today = date.today()
    result = await db.execute(
        select(SecurityReport).where(
            SecurityReport.user_id == current_user.id,
            SecurityReport.report_date == today,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        report = await generate_daily_report(current_user.id, today, db)
    return report


@router.get("/history", response_model=List[SecurityReportResponse])
async def get_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SecurityReport)
        .where(SecurityReport.user_id == current_user.id)
        .order_by(SecurityReport.report_date.desc())
        .limit(30)
    )
    return result.scalars().all()


@router.post("/log-behavior")
async def log_behavior_event(
    event_type: str,
    details: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Log a risky behavior event for behavioral risk scoring."""
    risk_map = {
        "clicked_unknown_link": 15.0,
        "installed_suspicious_app": 20.0,
        "shared_otp": 30.0,
        "connected_open_wifi": 10.0,
        "received_scam_call": 8.0,
        "submitted_form_on_suspicious_site": 25.0,
        "opened_scam_message": 12.0,
        "granted_excessive_permissions": 18.0,
        "disabled_security_feature": 22.0,
    }

    try:
        event_type_enum = BehaviorEventType(event_type)
    except ValueError:
        event_type_enum = BehaviorEventType.clicked_unknown_link

    event = BehaviorEvent(
        user_id=current_user.id,
        event_type=event_type_enum,
        risk_contribution=risk_map.get(event_type, 10.0),
        details=details,
    )
    db.add(event)
    await db.commit()
    return {"message": "Behavior event logged", "risk_contribution": risk_map.get(event_type, 10.0)}


@router.get("/weekly-insights")
async def get_weekly_insights(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a 7-day security trend analysis."""
    today = date.today()
    week_ago = today - timedelta(days=7)

    reports_result = await db.execute(
        select(SecurityReport).where(
            SecurityReport.user_id == current_user.id,
            SecurityReport.report_date >= week_ago,
        ).order_by(SecurityReport.report_date.asc())
    )
    reports = reports_result.scalars().all()

    if not reports:
        return {"message": "No data for the past week", "trend": "unknown", "daily_scores": []}

    scores = [r.overall_risk_score for r in reports]
    avg_score = sum(scores) / len(scores)
    trend = "improving" if scores[-1] < scores[0] else ("worsening" if scores[-1] > scores[0] else "stable")

    return {
        "period": f"{week_ago.isoformat()} to {today.isoformat()}",
        "average_risk_score": round(avg_score, 1),
        "trend": trend,
        "best_day": min(reports, key=lambda r: r.overall_risk_score).report_date.isoformat(),
        "worst_day": max(reports, key=lambda r: r.overall_risk_score).report_date.isoformat(),
        "total_threats": sum(r.threats_detected for r in reports),
        "total_links_scanned": sum(r.links_scanned for r in reports),
        "daily_scores": [
            {"date": r.report_date.isoformat(), "risk_score": r.overall_risk_score}
            for r in reports
        ],
    }
