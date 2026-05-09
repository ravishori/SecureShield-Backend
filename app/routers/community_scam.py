from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
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
            select(func.count()).select_from(CommunityScamReport).where(
                CommunityScamReport.phone_number == request.phone_number,
                CommunityScamReport.is_active == True,
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
                extra_data={"phone": request.phone_number, "report_count": report_count + 1},
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
    query = select(CommunityScamReport).where(CommunityScamReport.is_active == True)

    if city:
        query = query.where(CommunityScamReport.city.ilike(f"%{city}%"))
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
    query = select(CommunityScamReport).where(CommunityScamReport.is_active == True)
    if city:
        query = query.where(CommunityScamReport.city.ilike(f"%{city}%"))
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


@router.post("/{report_id}/upvote")
async def upvote_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CommunityScamReport).where(CommunityScamReport.id == uuid.UUID(report_id))
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.upvotes += 1
    await db.commit()
    return {"message": "Upvoted", "upvotes": report.upvotes}
