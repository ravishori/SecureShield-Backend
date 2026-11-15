"""Privacy endpoints: read and change consent decisions, and start a re-authenticated account deletion.

* ``GET  /auth/consents``           the user's current decision per purpose, and whether the mandatory acknowledgements are up to date
* ``PUT  /auth/consents``           record a decision. Optional purposes can be granted and withdrawn; the mandatory ones can only be
                                    (re)accepted at the current version (withdrawing them means deleting the account)
* ``POST /auth/me/delete/start``    send the re-authentication code that ``DELETE /auth/me`` requires
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.rate_limiter import check_otp_send_rate
from app.models.user import User
from app.routers.auth import _check_otp_send_ip, _mask, get_current_user
from app.schemas.auth import (
    ConsentItem,
    ConsentState,
    ConsentUpdateRequest,
    DeleteStartResponse,
)
from app.services import consent as cns
from app.services import identity as idn
from app.services.client_ip import client_ip_for
from app.services.logger_service import get_logger, log_error
from app.services.otp_service import deliver_otp

router = APIRouter(prefix="/auth", tags=["privacy"])
logger = get_logger(__name__)


async def _state(db: AsyncSession, user: User) -> ConsentState:
    latest = await cns.current_state(db, user.id)
    items = []
    for purpose in cns.REQUIRED_PURPOSES + cns.OPTIONAL_PURPOSES:
        row = latest.get(purpose)
        items.append(
            ConsentItem(
                purpose=purpose,
                required=purpose in cns.REQUIRED_PURPOSES,
                version=cns.VERSIONS[purpose],
                granted=None if row is None else row.granted,
                accepted_version=None if row is None else row.version,
                decided_at=None if row is None else row.created_at,
                up_to_date=row is not None and row.version == cns.VERSIONS[purpose],
            )
        )
    return ConsentState(
        items=items, required_up_to_date=cns.required_up_to_date(latest)
    )


@router.get("/consents", response_model=ConsentState)
async def get_consents(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _state(db, current_user)


@router.put("/consents", response_model=ConsentState)
async def put_consent(
    body: ConsentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.purpose not in cns.VERSIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unknown consent purpose.",
        )
    if body.version != cns.VERSIONS[body.purpose]:
        raise cns.stale_version_error()
    if body.purpose in cns.REQUIRED_PURPOSES and not body.granted:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The terms of service and privacy notice cannot be withdrawn while the account exists. "
            "You can delete your account instead.",
        )
    try:
        cns.add_decision(
            db,
            current_user.id,
            body.purpose,
            body.granted,
            cns.UPDATE if body.purpose in cns.REQUIRED_PURPOSES else cns.SETTINGS,
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Consent update failed",
            exc=exc,
            endpoint="/auth/consents",
            method="PUT",
            user_id=str(current_user.id),
        )
        raise HTTPException(
            status_code=500, detail="Could not save your choice. Please try again."
        )
    return await _state(db, current_user)


@router.post("/me/delete/start", response_model=DeleteStartResponse)
async def delete_start(
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Send the deletion re-authentication code to the account's VERIFIED e-mail (else verified phone). Nothing is deleted."""
    client_ip = client_ip_for(http_request, None)
    _check_otp_send_ip(client_ip)
    channel = idn.reauth_channel(current_user)
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Verify your email address or phone number before deleting your account (sign in again with a code).",
            headers={"X-Identity-Error": "no_verified_identifier"},
        )
    kind, identifier = channel
    check_otp_send_rate(identifier)
    try:
        code = await idn.issue_challenge(
            db,
            kind=kind,
            identifier=identifier,
            purpose=idn.DELETE_ACCOUNT,
            user_id=current_user.id,
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Deletion code could not be created",
            exc=exc,
            endpoint="/auth/me/delete/start",
            method="POST",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Could not start account deletion.")
    result = await deliver_otp(identifier, code)
    if not result.success:
        logger.warning("Deletion code delivery failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not send the verification code. Please try again later.",
        )
    return DeleteStartResponse(
        message="We sent a confirmation code. Nothing has been deleted yet.",
        identifier=_mask(identifier),
    )
