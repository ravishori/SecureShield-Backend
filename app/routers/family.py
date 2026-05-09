import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.family import FamilyMember
from app.models.alert import Alert
from app.schemas.family import FamilyMemberCreateRequest, FamilyMemberResponse
from app.schemas.alert import AlertResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/family", tags=["family"])


@router.post("/members", response_model=FamilyMemberResponse)
async def add_member(
    request: FamilyMemberCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    member_user_id = None
    if request.member_phone:
        result = await db.execute(select(User).where(User.phone == request.member_phone))
        member_user = result.scalar_one_or_none()
        if member_user:
            member_user_id = member_user.id

    member = FamilyMember(
        user_id=current_user.id,
        member_user_id=member_user_id,
        relationship=request.relationship,
        nickname=request.nickname,
        can_view_alerts=request.can_view_alerts,
        can_trigger_panic=request.can_trigger_panic,
        is_child_profile=getattr(request, 'is_child_profile', False),
        content_filter_enabled=getattr(request, 'content_filter_enabled', False),
        cyberbullying_alerts=getattr(request, 'cyberbullying_alerts', False),
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
        select(FamilyMember).where(FamilyMember.user_id == current_user.id)
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
            FamilyMember.id == uuid.UUID(member_id),
            FamilyMember.user_id == current_user.id,
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(member)
    await db.commit()
    return {"message": "Member removed"}


@router.get("/members/{member_id}/alerts", response_model=List[AlertResponse])
async def get_member_alerts(
    member_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify the member belongs to current user
    result = await db.execute(
        select(FamilyMember).where(
            FamilyMember.id == uuid.UUID(member_id),
            FamilyMember.user_id == current_user.id,
            FamilyMember.can_view_alerts == True,
        )
    )
    member = result.scalar_one_or_none()
    if not member or not member.member_user_id:
        raise HTTPException(status_code=404, detail="Member not found or alerts not permitted")

    result = await db.execute(
        select(Alert)
        .where(Alert.user_id == member.member_user_id)
        .order_by(Alert.created_at.desc())
        .limit(20)
    )
    return result.scalars().all()
