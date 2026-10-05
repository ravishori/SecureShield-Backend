"""Cyber Warriors Network — HTTP router.

Phase 1B foundation endpoints only. Victim-interaction endpoints
(assistance cases, case messaging) are deferred until safeguarding +
consent + moderation controls land in a later slice.

Endpoints:
  POST   /warriors/apply                    — authenticated user submits an application
  GET    /warriors/me/application           — authenticated user reads their own application
  GET    /warriors/me                       — authenticated warrior reads their profile

  Admin-gated:
  GET    /warriors/admin/applications       — list pending applications
  POST   /warriors/admin/applications/{id}/approve
  POST   /warriors/admin/applications/{id}/reject

Every admin state change writes a WarriorAuditLog row — append-only trail
of who did what and why.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies.warrior_rbac import require_warrior_role, get_current_warrior
from app.models.cyber_warrior import (
    ApplicationStatus,
    AuditAction,
    WarriorApplication,
    WarriorAuditLog,
    WarriorProfile,
    WarriorRole,
)
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.cyber_warrior import (
    ApplicationApprove,
    ApplicationReject,
    WarriorApplicationCreate,
    WarriorApplicationResponse,
    WarriorProfileResponse,
)
from app.services.logger_service import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/warriors", tags=["warriors"])


# ─── User-facing endpoints ────────────────────────────────────────────────


@router.post(
    "/apply",
    response_model=WarriorApplicationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_application(
    payload: WarriorApplicationCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit a Cyber Warriors volunteer application.

    Guard rails:
      • Schema validator already enforces age ≥ 18 and consent flags.
      • One open (pending) application per user — DB partial unique index
        would also reject, but we check first for a nicer error message.
    """
    # Reject if user already has an open application
    existing = await db.execute(
        select(WarriorApplication).where(
            WarriorApplication.user_id == current_user.id,
            WarriorApplication.status == ApplicationStatus.pending,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending Cyber Warriors application.",
        )

    # Reject if user already has an active profile
    existing_profile = await db.execute(
        select(WarriorProfile).where(
            WarriorProfile.user_id == current_user.id,
            WarriorProfile.is_active.is_(True),  # noqa: E712
        )
    )
    if existing_profile.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are already an active Cyber Warrior.",
        )

    application = WarriorApplication(
        user_id=current_user.id,
        full_name=payload.full_name.strip(),
        date_of_birth=payload.date_of_birth,
        phone=payload.phone.strip(),
        email=payload.email.lower(),
        city=payload.city,
        state=payload.state,
        preferred_role=payload.preferred_role,
        motivation=payload.motivation.strip(),
        skills=payload.skills,
        languages=payload.languages,
        availability_hours_per_week=payload.availability_hours_per_week,
        consent_bgcheck=payload.consent_bgcheck,
        consent_pii=payload.consent_pii,
        consent_safeguarding=payload.consent_safeguarding,
        status=ApplicationStatus.pending,
    )
    db.add(application)
    await db.flush()

    db.add(
        WarriorAuditLog(
            actor_user_id=current_user.id,
            subject_user_id=current_user.id,
            action=AuditAction.application_submitted,
            extra={
                "application_id": str(application.id),
                "preferred_role": payload.preferred_role.value,
            },
        )
    )
    await db.commit()
    await db.refresh(application)

    logger.info(f"Warrior application submitted by user {current_user.id}")
    return application


@router.get("/me/application", response_model=WarriorApplicationResponse | None)
async def get_my_application(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current user's most-recent application (any status), or null."""
    result = await db.execute(
        select(WarriorApplication)
        .where(WarriorApplication.user_id == current_user.id)
        .order_by(WarriorApplication.created_at.desc())
    )
    return result.scalars().first()


@router.get("/me", response_model=WarriorProfileResponse)
async def get_my_warrior_profile(
    profile: WarriorProfile = Depends(get_current_warrior),
):
    """Return the authenticated warrior's own profile."""
    return profile


# ─── Admin-gated endpoints ────────────────────────────────────────────────


@router.get(
    "/admin/applications",
    response_model=List[WarriorApplicationResponse],
)
async def list_pending_applications(
    _admin: WarriorProfile = Depends(require_warrior_role(WarriorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """List applications still awaiting review. Admin-only."""
    result = await db.execute(
        select(WarriorApplication)
        .where(WarriorApplication.status == ApplicationStatus.pending)
        .order_by(WarriorApplication.created_at.asc())
    )
    return result.scalars().all()


@router.post(
    "/admin/applications/{application_id}/approve",
    response_model=WarriorProfileResponse,
)
async def approve_application(
    application_id: uuid.UUID,
    payload: ApplicationApprove,
    admin: WarriorProfile = Depends(require_warrior_role(WarriorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Approve a pending application and create a WarriorProfile.

    Idempotent on repeat calls to the same already-approved application
    (returns 409) — admin can't silently double-approve by mistake.
    """
    app_row = await db.get(WarriorApplication, application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail="Application not found.")
    if app_row.status != ApplicationStatus.pending:
        raise HTTPException(
            status_code=409,
            detail=f"Application is already {app_row.status.value}.",
        )

    # Create the profile. UNIQUE(user_id) on warrior_profiles means a user
    # with a prior inactive profile can't be re-approved — admin must
    # reactivate the existing one instead.
    existing_profile = await db.execute(
        select(WarriorProfile).where(WarriorProfile.user_id == app_row.user_id)
    )
    if existing_profile.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=(
                "A warrior profile already exists for this user. "
                "Use the profile reactivate endpoint instead."
            ),
        )

    profile = WarriorProfile(
        user_id=app_row.user_id,
        application_id=app_row.id,
        role=payload.assigned_role,
        is_active=True,
        display_name=app_row.full_name,
        date_of_birth=app_row.date_of_birth,
    )
    app_row.status = ApplicationStatus.approved
    app_row.reviewer_user_id = admin.user_id
    app_row.reviewer_notes = payload.reviewer_notes
    app_row.reviewed_at = datetime.utcnow()

    db.add(profile)
    db.add(
        WarriorAuditLog(
            actor_user_id=admin.user_id,
            subject_user_id=app_row.user_id,
            action=AuditAction.application_approved,
            extra={
                "application_id": str(app_row.id),
                "assigned_role": payload.assigned_role.value,
            },
            reason=payload.reviewer_notes,
        )
    )
    await db.commit()
    await db.refresh(profile)
    logger.info(
        f"Warrior application {app_row.id} approved by admin "
        f"{admin.user_id} → user {app_row.user_id} is now a "
        f"{payload.assigned_role.value}"
    )
    return profile


@router.post(
    "/admin/applications/{application_id}/reject",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def reject_application(
    application_id: uuid.UUID,
    payload: ApplicationReject,
    admin: WarriorProfile = Depends(require_warrior_role(WarriorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Reject a pending application with a mandatory reason."""
    app_row = await db.get(WarriorApplication, application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail="Application not found.")
    if app_row.status != ApplicationStatus.pending:
        raise HTTPException(
            status_code=409,
            detail=f"Application is already {app_row.status.value}.",
        )

    app_row.status = ApplicationStatus.rejected
    app_row.reviewer_user_id = admin.user_id
    app_row.reviewer_notes = payload.reviewer_notes
    app_row.reviewed_at = datetime.utcnow()

    db.add(
        WarriorAuditLog(
            actor_user_id=admin.user_id,
            subject_user_id=app_row.user_id,
            action=AuditAction.application_rejected,
            extra={"application_id": str(app_row.id)},
            reason=payload.reviewer_notes,
        )
    )
    await db.commit()
    logger.info(f"Warrior application {app_row.id} rejected by admin {admin.user_id}")
