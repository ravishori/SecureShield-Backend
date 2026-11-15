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

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy import select, func, desc
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.app_install_event import AppInstallEvent
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.app_monitor import (
    AppEventPayload,
    EventOutcome,
    GuardianOutcome,
    BatchSyncRequest,
    BatchSyncResponse,
    AppEventResponse,
    MonitorHistoryResponse,
)
from app.routers.auth import get_current_user
from app.middleware.rate_limiter import rate_limiter
from app.models.elderly_config import ElderlyConfig
from app.services import guardian_alerts as rules
from app.services import guardian_outbox
from app.services.risk_engine import compute_risk
from app.services.clone_analyzer import analyze_clone

router = APIRouter(prefix="/app-monitor", tags=["app-monitor"])


def _ms_to_datetime(ms: int) -> datetime | None:
    """Epoch milliseconds -> naive UTC. None when implausible (before 2009 or more than a day in the future)."""
    try:
        if (
            ms < 1_230_000_000_000
            or ms > (datetime.utcnow().timestamp() + 86_400) * 1000
        ):
            return None
        return datetime.utcfromtimestamp(ms / 1000)
    except (OverflowError, OSError, ValueError):
        return None


@router.post("/sync", response_model=BatchSyncResponse)
async def batch_sync_events(
    request: BatchSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Offline-first batch sync (up to 50 events). SAFE TO RETRY.

    * Idempotent per user: an event carrying ``client_event_id`` is stored at most once (unique index, race-safe). Old clients
      that send no id are de-duplicated by the event's own observation time when they send one.
    * ``outcomes`` has one entry per request item, in order: ``created``, ``duplicate`` or ``rejected`` (a malformed event is
      rejected on its own and never fails the batch). ``synced`` and ``results`` keep their old meaning (created events only).
    * Each outcome carries an independent ``guardian`` status: the alert outbox is separate from history, so a duplicate or
      history failure never changes whether a guardian is told, and the other way round.
    * The whole call is one transaction: a server error rolls everything back, and the retry is safe.
    """
    if not rate_limiter.is_allowed(
        f"app_sync:{current_user.id}", max_hits=60, window_seconds=60
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many sync requests. Please retry shortly.",
            headers={"Retry-After": "60"},
        )

    cfg = (
        await db.execute(
            select(ElderlyConfig).where(ElderlyConfig.user_id == current_user.id)
        )
    ).scalar_one_or_none()
    now = datetime.utcnow()
    saved: List[AppInstallEvent] = []
    outcomes: List[EventOutcome] = []
    queued_any = False

    for index, raw in enumerate(request.events):
        # ── per-event validation ─────────────────────────────────────────────────────────────────────────────────────
        if isinstance(raw, AppEventPayload):
            ev = raw
        else:
            try:
                ev = AppEventPayload.model_validate(raw)
            except ValidationError as exc:
                fields = sorted(
                    {str(e["loc"][0]) for e in exc.errors() if e.get("loc")}
                )
                cid = None
                try:
                    cid = (
                        uuid.UUID(str(raw.get("client_event_id")))
                        if raw.get("client_event_id")
                        else None
                    )
                except (ValueError, AttributeError):
                    cid = None
                outcomes.append(
                    EventOutcome(
                        index=index,
                        client_event_id=cid,
                        status="rejected",
                        reason="invalid_payload",
                        fields=fields[:10],
                    )
                )
                continue

        occurred_ms = (
            ev.occurred_at if ev.occurred_at is not None else ev.client_timestamp
        )
        occurred = None
        if occurred_ms is not None:
            occurred = _ms_to_datetime(occurred_ms)
            if occurred is None:
                outcomes.append(
                    EventOutcome(
                        index=index,
                        client_event_id=ev.client_event_id,
                        status="rejected",
                        reason="bad_timestamp",
                        fields=["occurred_at"],
                    )
                )
                continue

        # ── legacy de-duplication for old clients with neither an id nor a timestamp ─────────────────────────────
        # Only a fresh install can be matched this way. Updates and removals carry the same first-install time every time,
        # so the old rule silently dropped real second updates; without an id or time they are now kept.
        if (
            ev.client_event_id is None
            and occurred is None
            and ev.event_type == "installed"
            and ev.first_install_time is not None
        ):
            dup_id = (
                await db.execute(
                    select(AppInstallEvent.id).where(
                        AppInstallEvent.user_id == current_user.id,
                        AppInstallEvent.package_name == ev.package_name,
                        AppInstallEvent.event_type == "installed",
                        AppInstallEvent.first_install_time == ev.first_install_time,
                    )
                )
            ).scalar_one_or_none()
            if dup_id is not None:
                outcomes.append(
                    EventOutcome(
                        index=index,
                        status="duplicate",
                        id=dup_id,
                        guardian=GuardianOutcome(status="none"),
                    )
                )
                continue

        clone = analyze_clone(package_name=ev.package_name, app_name=ev.app_name)
        risk = compute_risk(
            dangerous_perm_count=ev.perm_count,
            is_unknown_source=ev.is_unknown_source,
            installer=ev.installer_package,
            clone_probability=clone.overall_score,
            has_overlay=ev.has_overlay,
            has_accessibility=ev.has_accessibility,
        )
        is_clone = clone.verdict in ("likely_clone", "confirmed_clone")

        # ── atomic insert: the unique indexes decide, so two concurrent retries cannot both create the event ───────
        new_id = uuid.uuid4()
        values = dict(
            id=new_id,
            user_id=current_user.id,
            client_event_id=ev.client_event_id,
            occurred_at=occurred,
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
            flagged_as_clone=is_clone,
            clone_target_pkg=clone.target_package,
            has_overlay=ev.has_overlay,
            has_accessibility=ev.has_accessibility,
            first_install_time=ev.first_install_time,
            synced_at=now,
            created_at=now,
        )
        inserted = (
            await db.execute(
                pg_insert(AppInstallEvent)
                .values(**values)
                .on_conflict_do_nothing()  # either partial unique index
                .returning(AppInstallEvent.id)
            )
        ).first()

        if inserted is None:
            # already stored: find it (by id, or by the legacy occurrence key) and report its independent alert status
            q = select(AppInstallEvent.id).where(
                AppInstallEvent.user_id == current_user.id
            )
            if ev.client_event_id is not None:
                q = q.where(AppInstallEvent.client_event_id == ev.client_event_id)
            else:
                q = q.where(
                    AppInstallEvent.client_event_id.is_(None),
                    AppInstallEvent.package_name == ev.package_name,
                    AppInstallEvent.event_type == ev.event_type,
                    AppInstallEvent.occurred_at == occurred,
                )
            existing_id = (await db.execute(q)).scalar_one_or_none()
            g = None
            if existing_id is not None:
                st = await guardian_outbox.status_for_event(
                    db, current_user.id, existing_id
                )
                g = GuardianOutcome(status=st) if st else GuardianOutcome(status="none")
            outcomes.append(
                EventOutcome(
                    index=index,
                    client_event_id=ev.client_event_id,
                    status="duplicate",
                    id=existing_id,
                    guardian=g,
                )
            )
            continue

        event = (
            await db.execute(
                select(AppInstallEvent).where(AppInstallEvent.id == new_id)
            )
        ).scalar_one()
        saved.append(event)

        # ── auto-create alert for dangerous events (unchanged behaviour) ───────────────────────────────────────────
        if risk.level == "danger" or is_clone:
            title = (
                f"⚠️ Fake app detected: {ev.app_name}"
                if is_clone
                else f"🚨 High-risk app installed: {ev.app_name}"
            )
            db.add(
                Alert(
                    user_id=current_user.id,
                    alert_type=AlertType.app_risk,
                    severity=AlertSeverity.critical
                    if risk.level == "danger"
                    else AlertSeverity.warning,
                    title=title,
                    message="; ".join(risk.tags[:3])
                    or "Review this app before using it.",
                    extra_data={
                        "packageName": ev.package_name,
                        "riskScore": risk.score,
                        "cloneVerdict": clone.verdict,
                        "cloneTarget": clone.target_name,
                    },
                    is_read=False,
                )
            )

        # ── guardian alert: durable outbox row, independent of everything above ────────────────────────────────────
        guardian = GuardianOutcome(status="skipped", reason="not_applicable")
        if ev.event_type != "removed":
            # Eligibility uses the SERVER-calculated score only; the device-reported score is stored but never trusted.
            score = risk.score
            skip = rules.check_eligibility(cfg, score)
            when = occurred or now
            if skip:
                guardian = GuardianOutcome(
                    status="skipped", reason=rules.REASON_CODES[skip]
                )
            elif now - when > guardian_outbox.TTL:
                guardian = GuardianOutcome(status="expired", reason="too_old")
            else:
                _, created = await guardian_outbox.enqueue(
                    db,
                    user_id=current_user.id,
                    event_id=new_id,
                    dedupe_key=f"evt:{new_id}",
                    payload={
                        "app_name": ev.app_name,
                        "package_name": ev.package_name,
                        "risk_score": score,
                        "risk_level": risk.level,
                        "risk_tags": list(risk.tags)[:10],
                        "clone_verdict": clone.verdict if is_clone else None,
                        "occurred_at": when.isoformat(),
                    },
                    now=now,
                )
                guardian = GuardianOutcome(status="queued" if created else "already")
                queued_any = queued_any or created

        outcomes.append(
            EventOutcome(
                index=index,
                client_event_id=ev.client_event_id,
                status="created",
                id=new_id,
                guardian=guardian,
            )
        )

    await db.commit()
    if queued_any:
        # best-effort immediate attempt; the periodic worker is the durable path
        background_tasks.add_task(guardian_outbox.run_once_safe)

    return BatchSyncResponse(
        synced=len(saved),
        results=[_to_response(e) for e in saved],
        outcomes=outcomes,
    )


@router.get("/history", response_model=MonitorHistoryResponse)
async def get_history(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    risk_level: str | None = Query(None),  # filter: safe / warning / danger
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated install-event history for this user."""
    q = select(AppInstallEvent).where(AppInstallEvent.user_id == current_user.id)
    if risk_level:
        q = q.where(AppInstallEvent.risk_level == risk_level)
    q = q.order_by(desc(AppInstallEvent.created_at))

    total_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(total_q)).scalar_one()

    result = await db.execute(q.offset((page - 1) * limit).limit(limit))
    events = result.scalars().all()

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
    total = (await db.execute(base)).scalar_one()
    danger = (
        await db.execute(base.where(AppInstallEvent.risk_level == "danger"))
    ).scalar_one()
    warning = (
        await db.execute(base.where(AppInstallEvent.risk_level == "warning"))
    ).scalar_one()
    clones = (
        await db.execute(base.where(AppInstallEvent.flagged_as_clone.is_(True)))
    ).scalar_one()

    return {
        "total_monitored": total,
        "danger_count": danger,
        "warning_count": warning,
        "clone_count": clones,
        "safe_count": total - danger - warning,
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
