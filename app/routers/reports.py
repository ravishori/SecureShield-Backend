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
from app.schemas.security_report import SecurityReportResponse
from app.routers.auth import get_current_user

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

    # Calculate overall risk score
    overall_risk = min((threats_detected * 10 + apps_scanned * 0.5 + links_scanned * 2), 100.0)

    recommendations = [
        "Enable two-factor authentication on all accounts",
        "Avoid clicking unknown links from SMS or WhatsApp",
        "Never share OTPs with anyone, even bank officials",
        "Use strong unique passwords for each account",
        "Keep your apps updated to get security patches",
    ]

    top_threats = []
    if threats_detected > 0:
        top_threats.append({"type": "general", "count": threats_detected})
    if links_scanned > 0:
        top_threats.append({"type": "phishing_links", "count": links_scanned})
    if calls_analyzed > 0:
        top_threats.append({"type": "scam_calls", "count": calls_analyzed})

    report = SecurityReport(
        user_id=user_id,
        report_date=report_date,
        threats_detected=threats_detected,
        apps_scanned=apps_scanned,
        links_scanned=links_scanned,
        calls_analyzed=calls_analyzed,
        overall_risk_score=overall_risk,
        top_threats=top_threats,
        recommendations=recommendations,
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
