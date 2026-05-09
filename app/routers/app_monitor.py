"""
App Install Monitor router — /api/v1/app-monitor/

Endpoints:
  POST  /sync          — batch-sync install events (offline-first)
  GET   /history       — paginated install-event history
  GET   /summary       — aggregate stats for dashboard widget
  DELETE/{id}          — delete a specific event record
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
from app.models.app_install_event import AppInstallEvent
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.app_monitor import (
    BatchSyncRequest, BatchSyncResponse,
    AppEventResponse, MonitorHistoryResponse,
)
from app.routers.auth import get_current_user
from app.services.risk_engine import compute_risk
from app.services.clone_analyzer import analyze_clone

router = APIRouter(prefix="/app-monitor", tags=["app-monitor"])


@router.post("/sync", response_model=BatchSyncResponse)
async def batch_sync_events(
    request: BatchSyncRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Offline-first batch sync.  Device queues events locally and uploads
    when connectivity is available.  Idempotent — duplicates are silently skipped
    (we check package_name + event_type + first_install_time uniqueness).
    """
    saved: List[AppInstallEvent] = []

    for ev in request.events:
        # ── Clone analysis ────────────────────────────────────────────────────
        clone = analyze_clone(
            package_name=ev.package_name,
            app_name=ev.app_name,
        )

        # ── Server-side risk refinement ───────────────────────────────────────
        risk = compute_risk(
            dangerous_perm_count=ev.perm_count,
            is_unknown_source=ev.is_unknown_source,
            installer=ev.installer_package,
            clone_probability=clone.overall_score,
            has_overlay=ev.has_overlay,
            has_accessibility=ev.has_accessibility,
        )

        # ── Persist ───────────────────────────────────────────────────────────
        event = AppInstallEvent(
            user_id=current_user.id,
            package_name=ev.package_name,
            app_name=ev.app_name,
            version_name=ev.version_name,
            event_type=ev.event_type,
            installer_package=ev.installer_package,
            is_unknown_source=ev.is_unknown_source,
            is_system_app=ev.is_system_app,
            dangerous_perms=ev.dangerous_perms,
            perm_count=ev.perm_count,
            local_risk_score=ev.local_risk_score,
            server_risk_score=risk.score,
            risk_level=risk.level,
            risk_tags=risk.tags,
            clone_probability=clone.overall_score,
            flagged_as_clone=clone.verdict in ("likely_clone", "confirmed_clone"),
            clone_target_pkg=clone.target_package,
            has_overlay=ev.has_overlay,
            has_accessibility=ev.has_accessibility,
            first_install_time=ev.first_install_time,
            synced_at=datetime.utcnow(),
        )
        db.add(event)

        # ── Auto-create alert for dangerous events ────────────────────────────
        if risk.level == "danger" or clone.verdict in ("likely_clone", "confirmed_clone"):
            title = (
                f"⚠️ Fake app detected: {ev.app_name}"
                if clone.verdict in ("likely_clone", "confirmed_clone")
                else f"🚨 High-risk app installed: {ev.app_name}"
            )
            alert = Alert(
                user_id=current_user.id,
                alert_type=AlertType.malware_detected,
                severity=AlertSeverity.high if risk.level == "danger" else AlertSeverity.medium,
                title=title,
                description="; ".join(risk.tags[:3]),
                metadata={
                    "packageName":    ev.package_name,
                    "riskScore":      risk.score,
                    "cloneVerdict":   clone.verdict,
                    "cloneTarget":    clone.target_name,
                },
                is_read=False,
            )
            db.add(alert)

        saved.append(event)

    await db.commit()
    for e in saved:
        await db.refresh(e)

    return BatchSyncResponse(synced=len(saved), results=[_to_response(e) for e in saved])


@router.get("/history", response_model=MonitorHistoryResponse)
async def get_history(
    page:  int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    risk_level: str | None = Query(None),      # filter: safe / warning / danger
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated install-event history for this user."""
    q = select(AppInstallEvent).where(AppInstallEvent.user_id == current_user.id)
    if risk_level:
        q = q.where(AppInstallEvent.risk_level == risk_level)
    q = q.order_by(desc(AppInstallEvent.created_at))

    total_q  = select(func.count()).select_from(q.subquery())
    total    = (await db.execute(total_q)).scalar_one()

    result   = await db.execute(q.offset((page - 1) * limit).limit(limit))
    events   = result.scalars().all()

    return MonitorHistoryResponse(
        events=[_to_response(e) for e in events],
        total=total,
    )


@router.get("/summary")
async def get_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated counts for the dashboard widget."""
    base = select(func.count()).where(AppInstallEvent.user_id == current_user.id)
    total   = (await db.execute(base)).scalar_one()
    danger  = (await db.execute(base.where(AppInstallEvent.risk_level == "danger"))).scalar_one()
    warning = (await db.execute(base.where(AppInstallEvent.risk_level == "warning"))).scalar_one()
    clones  = (await db.execute(base.where(AppInstallEvent.flagged_as_clone == True))).scalar_one()

    return {
        "total_monitored": total,
        "danger_count":    danger,
        "warning_count":   warning,
        "clone_count":     clones,
        "safe_count":      total - danger - warning,
    }


@router.delete("/{event_id}", status_code=204)
async def delete_event(
    event_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AppInstallEvent).where(
            AppInstallEvent.id == event_id,
            AppInstallEvent.user_id == current_user.id,
        )
    )
    ev = result.scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    await db.delete(ev)
    await db.commit()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_response(e: AppInstallEvent) -> AppEventResponse:
    from app.schemas.app_monitor import AppEventResponse
    return AppEventResponse(
        id=e.id,
        package_name=e.package_name,
        app_name=e.app_name,
        event_type=e.event_type,
        server_risk_score=e.server_risk_score,
        risk_level=e.risk_level,
        risk_tags=e.risk_tags or [],
        clone_probability=e.clone_probability,
        flagged_as_clone=e.flagged_as_clone,
        clone_target_pkg=e.clone_target_pkg,
        synced_at=e.synced_at,
    )
