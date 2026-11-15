"""Consent purposes, the current notice versions, and how decisions are recorded.

REQUIRED purposes are acknowledgements without which the service cannot be provided (terms of service, privacy notice).
OPTIONAL purposes are separate, default-off choices; each can be given and withdrawn on its own and never gates sign-up.

Bump a version whenever the matching in-app text changes in a way that needs a new decision. The Flutter client carries the
same version strings (lib/features/privacy/privacy_content.dart); the server rejects a stale version so a user can never
"accept" text they were not shown.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_consent import UserConsent

TERMS = "terms"
PRIVACY = "privacy_notice"
AI_PROCESSING = "ai_processing"

REQUIRED_PURPOSES = (TERMS, PRIVACY)
OPTIONAL_PURPOSES = (AI_PROCESSING,)

VERSIONS = {
    TERMS: "2026-11-14",
    PRIVACY: "2026-11-14",
    AI_PROCESSING: "2026-11-14",
}

REGISTER = "register"
GOOGLE = "google"
SETTINGS = "settings"
UPDATE = "update"


def stale_version_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="The terms or privacy notice were updated. Please review the current version and accept it again.",
        headers={"X-Consent-Error": "stale_version"},
    )


def consent_required_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="You must accept the terms of service and acknowledge the privacy notice to create an account.",
        headers={"X-Consent-Error": "consent_required"},
    )


def check_required_versions(terms_version: str, privacy_version: str) -> None:
    if terms_version != VERSIONS[TERMS] or privacy_version != VERSIONS[PRIVACY]:
        raise stale_version_error()


def add_required(
    db: AsyncSession, user_id: uuid.UUID, source: str, at: datetime | None = None
) -> None:
    now = at or datetime.utcnow()
    for purpose in REQUIRED_PURPOSES:
        db.add(
            UserConsent(
                user_id=user_id,
                purpose=purpose,
                version=VERSIONS[purpose],
                granted=True,
                source=source,
                created_at=now,
            )
        )


def add_decision(
    db: AsyncSession,
    user_id: uuid.UUID,
    purpose: str,
    granted: bool,
    source: str,
    at: datetime | None = None,
) -> None:
    db.add(
        UserConsent(
            user_id=user_id,
            purpose=purpose,
            version=VERSIONS[purpose],
            granted=granted,
            source=source,
            created_at=at or datetime.utcnow(),
        )
    )


async def current_state(db: AsyncSession, user_id: uuid.UUID) -> dict[str, UserConsent]:
    """Newest decision per purpose."""
    rows = (
        (
            await db.execute(
                select(UserConsent)
                .where(UserConsent.user_id == user_id)
                .order_by(UserConsent.created_at, UserConsent.id)
            )
        )
        .scalars()
        .all()
    )
    latest: dict[str, UserConsent] = {}
    for r in rows:
        latest[r.purpose] = r
    return latest


def required_up_to_date(latest: dict[str, UserConsent]) -> bool:
    return all(
        (c := latest.get(p)) is not None and c.granted and c.version == VERSIONS[p]
        for p in REQUIRED_PURPOSES
    )
