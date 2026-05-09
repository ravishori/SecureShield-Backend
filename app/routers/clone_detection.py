"""
Clone / Fake-App Detection router — /api/v1/clone-detection/

Endpoints:
  POST  /scan            — on-demand single-app clone scan
  GET   /history         — user's clone-scan history
  POST  /feedback        — user confirms / dismisses a clone finding
  GET   /catalogue       — return the known-legitimate-apps catalogue (for local caching)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.clone_report import CloneReport
from app.schemas.clone_detection import (
    CloneScanRequest, CloneScanResponse,
    CloneHistoryResponse, CloneFeedbackRequest,
)
from app.routers.auth import get_current_user
from app.services.clone_analyzer import analyze_clone, KNOWN_APPS

router = APIRouter(prefix="/clone-detection", tags=["clone-detection"])


def _action_recommended(verdict: str) -> str:
    return {
        "confirmed_clone": "uninstall",
        "likely_clone":    "block",
        "suspicious":      "warn",
        "safe":            "none",
    }.get(verdict, "none")


@router.post("/scan", response_model=CloneScanResponse)
async def scan_app(
    request: CloneScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyse a single app for clone / impersonation signals."""
    result = analyze_clone(
        package_name=request.package_name,
        app_name=request.app_name,
        cert_hash=request.cert_hash,
        icon_perceptual_hash=request.icon_phash,
    )

    report = CloneReport(
        user_id=current_user.id,
        package_name=request.package_name,
        app_name=request.app_name,
        target_package=result.target_package,
        target_name=result.target_name,
        name_similarity=result.name_similarity,
        package_similarity=result.package_similarity,
        icon_hash_match=False,   # populated when icon-hash DB is in place
        cert_hash_match=result.verdict == "confirmed_clone" and bool(request.cert_hash),
        overall_score=result.overall_score,
        verdict=result.verdict,
        signals=result.signals,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return _to_response(report)


@router.get("/history", response_model=CloneHistoryResponse)
async def get_history(
    page:    int = Query(1, ge=1),
    limit:   int = Query(20, ge=1, le=100),
    verdict: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(CloneReport).where(CloneReport.user_id == current_user.id)
    if verdict:
        q = q.where(CloneReport.verdict == verdict)
    q = q.order_by(desc(CloneReport.created_at))

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows  = (await db.execute(q.offset((page - 1) * limit).limit(limit))).scalars().all()

    return CloneHistoryResponse(reports=[_to_response(r) for r in rows], total=total)


@router.post("/feedback", status_code=200)
async def submit_feedback(
    request: CloneFeedbackRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Record user's verdict on a clone finding (crowdsourced signal)."""
    result = await db.execute(
        select(CloneReport).where(
            CloneReport.id == request.report_id,
            CloneReport.user_id == current_user.id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.user_confirmed = request.user_confirmed
    report.action_taken   = request.action_taken
    await db.commit()
    return {"status": "ok"}


@router.get("/catalogue")
async def get_catalogue(_: User = Depends(get_current_user)):
    """
    Return the known-legitimate-apps catalogue.
    Devices cache this locally for offline clone detection.
    """
    return {
        "version": "2025-05-06",
        "count":   len(KNOWN_APPS),
        "apps":    [{"packageName": k, "displayName": v} for k, v in KNOWN_APPS.items()],
    }


# ── Helper ────────────────────────────────────────────────────────────────────

def _to_response(r: CloneReport) -> CloneScanResponse:
    return CloneScanResponse(
        id=r.id,
        package_name=r.package_name,
        app_name=r.app_name,
        target_package=r.target_package,
        target_name=r.target_name,
        name_similarity=r.name_similarity,
        package_similarity=r.package_similarity,
        overall_score=r.overall_score,
        verdict=r.verdict,
        signals=r.signals or [],
        action_recommended=_action_recommended(r.verdict),
        created_at=r.created_at,
    )
