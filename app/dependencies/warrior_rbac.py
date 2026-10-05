"""Role-based access control for the Cyber Warriors Network.

Exports two FastAPI dependencies:

  • ``require_warrior_role(min_role)`` — returns a dependency callable that
    (1) resolves the current user via get_current_user,
    (2) looks up their WarriorProfile,
    (3) asserts the profile is active AND role meets ``min_role``.
    Returns the WarriorProfile on success, raises 403 on failure.

  • ``get_current_warrior`` — convenience wrapping ``require_warrior_role``
    at the lowest tier (trainee). Use when you just need "is a warrior".

Safeguarding guard rail: by model definition a WarriorProfile only exists
for approved adult applicants (the application schema validator rejects
underage DoB and the approval route re-checks). The guard treats
"no profile" as "unauthorised" with a consistent 403 — never leaks
whether the caller is a minor, has a pending application, or was
rejected. All three look the same from the outside.
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cyber_warrior import WarriorProfile, WarriorRole, role_meets
from app.models.user import User
from app.routers.auth import get_current_user


def require_warrior_role(min_role: WarriorRole) -> Callable:
    """Build a FastAPI dependency enforcing a minimum warrior role.

    Usage::

        @router.get("/warriors/dashboard")
        async def dashboard(
            profile: WarriorProfile = Depends(
                require_warrior_role(WarriorRole.trainee)
            ),
        ):
            ...
    """

    async def _dep(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> WarriorProfile:
        result = await db.execute(
            select(WarriorProfile).where(WarriorProfile.user_id == current_user.id)
        )
        profile = result.scalar_one_or_none()

        if profile is None or not profile.is_active:
            # Same 403 for "no profile" and "suspended profile" — never
            # reveal which to the caller. Admin UIs that need distinction
            # should use a dedicated admin endpoint.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cyber Warriors access denied.",
            )

        if not role_meets(profile.role, min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient role. This endpoint requires "
                    f"'{min_role.value}' or higher; your current role is "
                    f"'{profile.role.value}'."
                ),
            )

        return profile

    return _dep


# Lowest-tier convenience — "just needs to be a warrior at all"
get_current_warrior = require_warrior_role(WarriorRole.trainee)
