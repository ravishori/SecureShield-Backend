import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert, AlertSeverity
from app.models.family import FamilyMember
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.alert import AlertResponse
from app.schemas.family import (
    FamilyDashboard,
    FamilyDashboardMember,
    FamilyInvitation,
    FamilyMemberCreateRequest,
    FamilyMemberResponse,
)
from app.services.otp_service import _normalize_phone

router = APIRouter(prefix="/family", tags=["family"])

MAX_FAMILY_MEMBERS = 20
ACCEPTED = "accepted"


def _uuid_or_404(value: str, what: str = "Member") -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"{what} not found")


@router.post("/members", response_model=FamilyMemberResponse)
async def add_member(
    request: FamilyMemberCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Invite someone. The link stays 'pending' (and grants nothing) until THEY accept."""
    phone = _normalize_phone(request.member_phone) if request.member_phone else None
    if phone and not (
        phone.startswith("+") and phone[1:].isdigit() and 7 <= len(phone) <= 20
    ):
        raise HTTPException(
            status_code=422, detail="member_phone is not a valid phone number"
        )
    if not phone and not request.nickname:
        raise HTTPException(
            status_code=422, detail="Provide a phone number or a nickname"
        )

    count = (
        await db.execute(
            select(func.count(FamilyMember.id)).where(
                FamilyMember.user_id == current_user.id
            )
        )
    ).scalar_one()
    if count >= MAX_FAMILY_MEMBERS:
        raise HTTPException(
            status_code=409,
            detail=f"At most {MAX_FAMILY_MEMBERS} family members are allowed",
        )

    member_user_id = None
    if phone:
        if phone == current_user.phone:
            raise HTTPException(status_code=422, detail="You cannot add yourself")
        invited = (
            await db.execute(select(User).where(User.phone == phone))
        ).scalar_one_or_none()
        if invited:
            member_user_id = invited.id
        same = FamilyMember.invited_phone == phone
        if member_user_id:
            same = or_(same, FamilyMember.member_user_id == member_user_id)
        dup = (
            await db.execute(
                select(FamilyMember.id).where(
                    FamilyMember.user_id == current_user.id, same
                )
            )
        ).first()
        if dup:
            raise HTTPException(
                status_code=409, detail="This person is already in your family list"
            )

    member = FamilyMember(
        user_id=current_user.id,
        member_user_id=member_user_id,
        invited_phone=phone,
        consent_status="pending",
        relationship=request.relationship,
        nickname=request.nickname,
        can_view_alerts=request.can_view_alerts,
        can_trigger_panic=request.can_trigger_panic,
        is_child_profile=request.is_child_profile,
        content_filter_enabled=request.content_filter_enabled,
        cyberbullying_alerts=request.cyberbullying_alerts,
    )
    db.add(member)
    await db.commit()
    await db.refresh(member)
    return member


@router.get("/members", response_model=List[FamilyMemberResponse])
async def list_members(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(FamilyMember)
        .where(FamilyMember.user_id == current_user.id)
        .order_by(FamilyMember.created_at)
    )
    return result.scalars().all()


@router.delete("/members/{member_id}")
async def remove_member(
    member_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(FamilyMember).where(
            FamilyMember.id == _uuid_or_404(member_id),
            FamilyMember.user_id == current_user.id,
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(member)
    await db.commit()
    return {"message": "Member removed"}


# -- Invitee side: consent ---------------------------------------------------
def _addressed_to(user: User):
    cond = [FamilyMember.member_user_id == user.id]
    if user.phone:
        cond.append(FamilyMember.invited_phone == user.phone)
    return or_(*cond)


@router.get("/invitations", response_model=List[FamilyInvitation])
async def list_invitations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(FamilyMember, User)
            .join(User, User.id == FamilyMember.user_id)
            .where(
                _addressed_to(current_user), FamilyMember.consent_status == "pending"
            )
            .order_by(FamilyMember.created_at.desc())
        )
    ).all()
    return [
        FamilyInvitation(
            id=m.id,
            inviter_name=inviter.full_name,
            relationship=m.relationship,
            can_view_alerts=m.can_view_alerts,
            can_trigger_panic=m.can_trigger_panic,
            created_at=m.created_at,
        )
        for m, inviter in rows
    ]


async def _link_for(db: AsyncSession, user: User, link_id: str) -> FamilyMember:
    member = (
        await db.execute(
            select(FamilyMember).where(
                FamilyMember.id == _uuid_or_404(link_id, "Invitation"),
                _addressed_to(user),
            )
        )
    ).scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Invitation not found")
    return member


@router.post("/invitations/{invitation_id}/accept")
async def accept_invitation(
    invitation_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    member = await _link_for(db, current_user, invitation_id)
    member.member_user_id = current_user.id
    member.consent_status = ACCEPTED
    await db.commit()
    return {"message": "Invitation accepted"}


@router.post("/invitations/{invitation_id}/decline")
async def decline_invitation(
    invitation_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    member = await _link_for(db, current_user, invitation_id)
    member.consent_status = "declined"
    await db.commit()
    return {"message": "Invitation declined"}


@router.post("/links/{link_id}/revoke")
async def revoke_my_consent(
    link_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The monitored person can withdraw access at any time."""
    member = await _link_for(db, current_user, link_id)
    member.consent_status = "declined"
    await db.commit()
    return {"message": "Access revoked"}


# -- Inviter side: alerts + dashboard (only with consent) ---------------------
@router.get("/members/{member_id}/alerts", response_model=List[AlertResponse])
async def get_member_alerts(
    member_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(FamilyMember).where(
            FamilyMember.id == _uuid_or_404(member_id),
            FamilyMember.user_id == current_user.id,
            FamilyMember.can_view_alerts.is_(True),
            FamilyMember.consent_status == ACCEPTED,
        )
    )
    member = result.scalar_one_or_none()
    if not member or not member.member_user_id:
        raise HTTPException(
            status_code=404, detail="Member not found or alerts not permitted"
        )

    result = await db.execute(
        select(Alert)
        .where(Alert.user_id == member.member_user_id, Alert.is_dismissed.is_(False))
        .order_by(Alert.created_at.desc())
        .limit(20)
    )
    return result.scalars().all()


@router.get("/dashboard", response_model=FamilyDashboard)
async def family_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    members = (
        (
            await db.execute(
                select(FamilyMember)
                .where(FamilyMember.user_id == current_user.id)
                .order_by(FamilyMember.created_at)
            )
        )
        .scalars()
        .all()
    )
    out: List[FamilyDashboardMember] = []
    for m in members:
        visible = bool(
            m.can_view_alerts and m.consent_status == ACCEPTED and m.member_user_id
        )
        row = FamilyDashboardMember(
            member_id=m.id,
            nickname=m.nickname,
            relationship=m.relationship,
            consent_status=m.consent_status,
            alerts_visible=visible,
        )
        if visible:
            base = (Alert.user_id == m.member_user_id, Alert.is_dismissed.is_(False))
            row.unread_alerts = (
                await db.execute(
                    select(func.count(Alert.id)).where(*base, Alert.is_read.is_(False))
                )
            ).scalar_one()
            row.critical_alerts = (
                await db.execute(
                    select(func.count(Alert.id)).where(
                        *base,
                        Alert.is_read.is_(False),
                        Alert.severity == AlertSeverity.critical,
                    )
                )
            ).scalar_one()
            latest = (
                await db.execute(
                    select(Alert)
                    .where(*base)
                    .order_by(Alert.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if latest:
                row.latest_alert_title, row.latest_alert_at = (
                    latest.title,
                    latest.created_at,
                )
        out.append(row)
    return FamilyDashboard(
        members=out,
        total_unread_alerts=sum(r.unread_alerts for r in out),
        total_critical_alerts=sum(r.critical_alerts for r in out),
        pending_invitations_sent=sum(1 for r in out if r.consent_status == "pending"),
    )
