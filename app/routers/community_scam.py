from collections import Counter
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.user import User
from app.models.community_scam import CommunityScamReport, ScamType
from app.models.alert import Alert, AlertType, AlertSeverity
from app.routers.auth import get_current_user

router = APIRouter(prefix="/community-scams", tags=["community-scams"])


class ScamReportRequest(BaseModel):
    scam_type: ScamType
    title: str
    description: str
    phone_number: Optional[str] = None
    url: Optional[str] = None
    city: Optional[str] = None
    pincode: Optional[str] = None


class ScamReportResponse(BaseModel):
    id: str
    scam_type: str
    title: str
    description: str
    phone_number: Optional[str]
    url: Optional[str]
    city: Optional[str]
    pincode: Optional[str]
    upvotes: int
    is_verified: bool
    created_at: str

    class Config:
        from_attributes = True


@router.post("/report", response_model=ScamReportResponse)
async def report_scam(
    request: ScamReportRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    report = CommunityScamReport(
        user_id=current_user.id,
        scam_type=request.scam_type,
        title=request.title,
        description=request.description,
        phone_number=request.phone_number,
        url=request.url,
        city=request.city,
        pincode=request.pincode,
    )
    db.add(report)

    # Check if this scam number/URL has been reported 5+ times — broadcast alert
    if request.phone_number:
        count_result = await db.execute(
            select(func.count())
            .select_from(CommunityScamReport)
            .where(
                CommunityScamReport.phone_number == request.phone_number,
                CommunityScamReport.is_active.is_(True),
            )
        )
        report_count = count_result.scalar() or 0
        if report_count >= 4:  # This is the 5th report
            alert = Alert(
                user_id=current_user.id,
                alert_type=AlertType.community_scam,
                title="Community Scam Alert Verified",
                message=f"Phone {request.phone_number} has been reported as a scam {report_count + 1} times in your community.",
                severity=AlertSeverity.critical,
                extra_data={
                    "phone": request.phone_number,
                    "report_count": report_count + 1,
                },
            )
            db.add(alert)

    await db.commit()
    await db.refresh(report)

    return ScamReportResponse(
        id=str(report.id),
        scam_type=report.scam_type.value,
        title=report.title,
        description=report.description,
        phone_number=report.phone_number,
        url=report.url,
        city=report.city,
        pincode=report.pincode,
        upvotes=report.upvotes,
        is_verified=report.is_verified,
        created_at=report.created_at.isoformat(),
    )


@router.get("/feed", response_model=List[ScamReportResponse])
async def get_community_feed(
    city: Optional[str] = Query(None),
    pincode: Optional[str] = Query(None),
    scam_type: Optional[ScamType] = Query(None),
    limit: int = Query(30, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(CommunityScamReport).where(CommunityScamReport.is_active.is_(True))

    if city:
        query = query.where(
            CommunityScamReport.city.ilike(f"%{_like_escape(city)}%", escape="\\")
        )
    if pincode:
        query = query.where(CommunityScamReport.pincode == pincode)
    if scam_type:
        query = query.where(CommunityScamReport.scam_type == scam_type)

    query = query.order_by(CommunityScamReport.created_at.desc()).limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()

    return [
        ScamReportResponse(
            id=str(r.id),
            scam_type=r.scam_type.value,
            title=r.title,
            description=r.description,
            phone_number=r.phone_number,
            url=r.url,
            city=r.city,
            pincode=r.pincode,
            upvotes=r.upvotes,
            is_verified=r.is_verified,
            created_at=r.created_at.isoformat(),
        )
        for r in reports
    ]


@router.get("/trending", response_model=List[ScamReportResponse])
async def get_trending_scams(
    city: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(CommunityScamReport).where(CommunityScamReport.is_active.is_(True))
    if city:
        query = query.where(
            CommunityScamReport.city.ilike(f"%{_like_escape(city)}%", escape="\\")
        )
    query = query.order_by(CommunityScamReport.upvotes.desc()).limit(10)
    result = await db.execute(query)
    reports = result.scalars().all()

    return [
        ScamReportResponse(
            id=str(r.id),
            scam_type=r.scam_type.value,
            title=r.title,
            description=r.description,
            phone_number=r.phone_number,
            url=r.url,
            city=r.city,
            pincode=r.pincode,
            upvotes=r.upvotes,
            is_verified=r.is_verified,
            created_at=r.created_at.isoformat(),
        )
        for r in reports
    ]


MIN_CORROBORATING_REPORTS = 2


def _like_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ScamNewsItem(BaseModel):
    id: str
    headline: str
    summary: str
    scam_type: str
    severity: str  # info | warning | critical
    region: Optional[str]
    source: str  # "community" | "editorial" | "regulator"
    reports_in_period: int
    sample_phones: List[str]
    sample_urls: List[str]
    week_starting: str


class ScamNewsResponse(BaseModel):
    week_starting: str
    week_ending: str
    items: List[ScamNewsItem]
    total_reports_this_week: int
    top_city: Optional[str]
    advisory: str


# ─── Editorial defaults: nationwide scam advisories curated by SecureShield ───
# These are shown when there isn't enough community data to drive the feed.
# Update this list as new scam categories surface in India.
_EDITORIAL_NEWS: List[dict] = [
    {
        "headline": "Digital Arrest scams are rising across India",
        "summary": (
            "Fraudsters posing as CBI/Customs/Police on WhatsApp or Skype video "
            "calls coerce victims into 'house arrest' until they transfer money. "
            "No Indian agency arrests over a video call — disconnect immediately."
        ),
        "scam_type": "other",
        "severity": "critical",
        "region": "All India",
        "source": "editorial",
    },
    {
        "headline": "Fake bank SMS from 10-digit numbers",
        "summary": (
            "Banks send SMS only from TRAI headers (VK-HDFCBK etc.). A 10-digit "
            "sender claiming 'KYC expired — update now' with a bit.ly link is a "
            "phishing attempt. Verify by calling the number on your card."
        ),
        "scam_type": "phishing_link",
        "severity": "warning",
        "region": "All India",
        "source": "editorial",
    },
    {
        "headline": "Task-based job scams on Telegram",
        "summary": (
            "Fake 'work from home — earn ₹3000/day' messages route victims to "
            "Telegram channels where small initial payouts build trust, then a "
            "large 'refundable deposit' disappears. Currently the fastest "
            "growing scam category in India."
        ),
        "scam_type": "fake_job",
        "severity": "critical",
        "region": "All India",
        "source": "editorial",
    },
    {
        "headline": "Fake payment screenshot at QR-pay merchants",
        "summary": (
            "Customers show edited UPI 'success' screens to shopkeepers, who "
            "release goods before the inflow lands. Use the in-app Payment "
            "Verifier to OCR-check before delivery."
        ),
        "scam_type": "bank_fraud",
        "severity": "warning",
        "region": "All India",
        "source": "editorial",
    },
    {
        "headline": "FedEx 'illegal parcel' calls escalating",
        "summary": (
            "Caller claims a parcel in your name was seized at customs with "
            "narcotics inside; transfers the call to 'CBI'. Always a scam — "
            "report on 1930."
        ),
        "scam_type": "parcel_scam",
        "severity": "critical",
        "region": "All India",
        "source": "editorial",
    },
]


@router.get("/news-feed", response_model=ScamNewsResponse)
async def get_scam_news_feed(
    city: Optional[str] = Query(
        None, max_length=80, description="Filter community trends by city"
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate community reports from the last 7 days into a news feed.

    Combines:
      - Top trending scam categories from community reports (by count)
      - Editorial advisories for nationwide scam types
      - Top city by report volume
    """
    now = datetime.utcnow()
    week_start = now - timedelta(days=7)

    # Base query for active reports in the last 7 days
    base = select(CommunityScamReport).where(
        CommunityScamReport.is_active.is_(True),
        CommunityScamReport.created_at >= week_start,
    )
    if city:
        base = base.where(
            CommunityScamReport.city.ilike(f"%{_like_escape(city)}%", escape="\\")
        )

    # ── Aggregate by scam_type ──────────────────────────────────────────
    agg = select(
        CommunityScamReport.scam_type,
        func.count(CommunityScamReport.id).label("cnt"),
    ).where(
        CommunityScamReport.is_active.is_(True),
        CommunityScamReport.created_at >= week_start,
    )
    if city:
        agg = agg.where(
            CommunityScamReport.city.ilike(f"%{_like_escape(city)}%", escape="\\")
        )
    agg = agg.group_by(CommunityScamReport.scam_type).order_by(
        func.count(CommunityScamReport.id).desc()
    )
    agg_rows = (await db.execute(agg)).all()

    # ── Sample phones/URLs for the top scam type ────────────────────────
    items: List[ScamNewsItem] = []
    total_reports = 0
    for stype, cnt in agg_rows[:6]:
        total_reports += cnt
        sample_q = (
            select(CommunityScamReport)
            .where(
                CommunityScamReport.is_active.is_(True),
                CommunityScamReport.created_at >= week_start,
                CommunityScamReport.scam_type == stype,
            )
            .order_by(CommunityScamReport.upvotes.desc())
            .limit(5)
        )
        if city:
            sample_q = sample_q.where(
                CommunityScamReport.city.ilike(f"%{_like_escape(city)}%", escape="\\")
            )
        samples = (await db.execute(sample_q)).scalars().all()

        # Community reports are unverified: only surface a number/URL that at least two
        # separate reports name, so one malicious report cannot publicly label someone.
        phone_counts = Counter(s.phone_number for s in samples if s.phone_number)
        url_counts = Counter(s.url for s in samples if s.url)
        phones = sorted(
            p for p, n in phone_counts.items() if n >= MIN_CORROBORATING_REPORTS
        )[:3]
        urls = sorted(
            u for u, n in url_counts.items() if n >= MIN_CORROBORATING_REPORTS
        )[:3]
        headline_text = samples[0].title if samples else f"{stype.value} reports rising"
        summary_text = (
            f"{cnt} community report{'s' if cnt != 1 else ''} this week"
            f"{f' in {city}' if city else ''}. "
            f"{(samples[0].description[:140] + '…') if samples and len(samples[0].description) > 140 else (samples[0].description if samples else '')}"
        )

        severity = "critical" if cnt >= 10 else "warning" if cnt >= 3 else "info"

        items.append(
            ScamNewsItem(
                id=f"community-{stype.value}-{week_start.date().isoformat()}",
                headline=headline_text,
                summary=summary_text,
                scam_type=stype.value,
                severity=severity,
                region=city or "All India",
                source="community",
                reports_in_period=cnt,
                sample_phones=phones,
                sample_urls=urls,
                week_starting=week_start.date().isoformat(),
            )
        )

    # ── Append editorial items not already covered by community ─────────
    seen_types = {it.scam_type for it in items}
    for ed in _EDITORIAL_NEWS:
        if ed["scam_type"] in seen_types and len(items) >= 5:
            continue
        items.append(
            ScamNewsItem(
                id=f"editorial-{ed['scam_type']}-{week_start.date().isoformat()}",
                headline=ed["headline"],
                summary=ed["summary"],
                scam_type=ed["scam_type"],
                severity=ed["severity"],
                region=ed["region"],
                source=ed["source"],
                reports_in_period=0,
                sample_phones=[],
                sample_urls=[],
                week_starting=week_start.date().isoformat(),
            )
        )

    # ── Top city by volume (nation-wide) ────────────────────────────────
    city_q = (
        select(
            CommunityScamReport.city,
            func.count(CommunityScamReport.id).label("cnt"),
        )
        .where(
            CommunityScamReport.is_active.is_(True),
            CommunityScamReport.created_at >= week_start,
            CommunityScamReport.city.isnot(None),
        )
        .group_by(CommunityScamReport.city)
        .order_by(func.count(CommunityScamReport.id).desc())
        .limit(1)
    )
    city_row = (await db.execute(city_q)).first()
    top_city = city_row[0] if city_row else None

    advisory = (
        f"{total_reports} community-reported scams this week"
        f"{f' (most from {top_city})' if top_city else ''}. "
        "Stay vigilant. When in doubt, call 1930."
    )

    return ScamNewsResponse(
        week_starting=week_start.date().isoformat(),
        week_ending=now.date().isoformat(),
        items=items[:8],
        total_reports_this_week=total_reports,
        top_city=top_city,
        advisory=advisory,
    )


@router.post("/{report_id}/upvote")
async def upvote_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CommunityScamReport).where(
            CommunityScamReport.id == uuid.UUID(report_id)
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.upvotes += 1
    await db.commit()
    return {"message": "Upvoted", "upvotes": report.upvotes}
