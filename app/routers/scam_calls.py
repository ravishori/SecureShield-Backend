from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.scam_call import ScamCall
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.scam_call import ScamCallReportRequest, ScamCallResponse
from app.routers.auth import get_current_user
from app.services.threat_analyzer import analyze_scam_call

router = APIRouter(prefix="/scam-calls", tags=["scam-calls"])


@router.post("/report", response_model=ScamCallResponse)
async def report_scam_call(
    request: ScamCallReportRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    risk_score, detection_reason = analyze_scam_call(
        request.caller_number,
        request.call_duration_seconds,
        request.audio_features,
    )

    if request.detection_reason:
        detection_reason = request.detection_reason

    scam_call = ScamCall(
        user_id=current_user.id,
        caller_number=request.caller_number,
        call_duration_seconds=request.call_duration_seconds,
        risk_score=risk_score,
        is_blocked=risk_score >= 70,
        detection_reason=detection_reason,
        audio_features=request.audio_features,
    )
    db.add(scam_call)

    if risk_score >= 50:
        alert = Alert(
            user_id=current_user.id,
            alert_type=AlertType.scam_call,
            title=f"Potential Scam Call: {request.caller_number}",
            message=f"A call from {request.caller_number} was flagged. Risk score: {risk_score:.0f}/100. {detection_reason}",
            severity=AlertSeverity.critical if risk_score >= 70 else AlertSeverity.warning,
            extra_data={"caller_number": request.caller_number, "risk_score": risk_score},
        )
        db.add(alert)

    await db.commit()
    await db.refresh(scam_call)
    return scam_call


@router.get("/history", response_model=List[ScamCallResponse])
async def get_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScamCall)
        .where(ScamCall.user_id == current_user.id)
        .order_by(ScamCall.detected_at.desc())
        .limit(50)
    )
    return result.scalars().all()


@router.post("/block/{number}")
async def block_number(
    number: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScamCall).where(
            ScamCall.user_id == current_user.id,
            ScamCall.caller_number == number,
        ).order_by(ScamCall.detected_at.desc())
    )
    scam_call = result.scalar_one_or_none()

    if scam_call:
        scam_call.is_blocked = True
        await db.commit()
        return {"message": f"Number {number} blocked"}

    # Create a new blocked entry
    scam_call = ScamCall(
        user_id=current_user.id,
        caller_number=number,
        call_duration_seconds=0,
        risk_score=100.0,
        is_blocked=True,
        detection_reason="Manually blocked by user",
    )
    db.add(scam_call)
    await db.commit()
    return {"message": f"Number {number} blocked"}
