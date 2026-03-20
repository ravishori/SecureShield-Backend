from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import uuid

from app.database import get_db
from app.models.user import User
from app.models.otp_vault import OtpVaultEntry
from app.schemas.otp_vault import OtpVaultCreateRequest, OtpVaultResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/otp-vault", tags=["otp-vault"])


@router.get("/entries", response_model=List[OtpVaultResponse])
async def get_entries(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OtpVaultEntry)
        .where(OtpVaultEntry.user_id == current_user.id, OtpVaultEntry.is_archived == False)
        .order_by(OtpVaultEntry.created_at.desc())
    )
    return result.scalars().all()


@router.post("/entries", response_model=OtpVaultResponse)
async def add_entry(
    request: OtpVaultCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    entry = OtpVaultEntry(
        user_id=current_user.id,
        sender=request.sender,
        raw_otp=request.raw_otp,
        encrypted_content=request.encrypted_content,
        source_app=request.source_app,
        received_at=request.received_at,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


@router.patch("/entries/{entry_id}/read", response_model=OtpVaultResponse)
async def mark_read(
    entry_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OtpVaultEntry).where(
            OtpVaultEntry.id == uuid.UUID(entry_id),
            OtpVaultEntry.user_id == current_user.id,
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    entry.is_read = True
    await db.commit()
    await db.refresh(entry)
    return entry


@router.delete("/entries/{entry_id}")
async def delete_entry(
    entry_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OtpVaultEntry).where(
            OtpVaultEntry.id == uuid.UUID(entry_id),
            OtpVaultEntry.user_id == current_user.id,
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    await db.delete(entry)
    await db.commit()
    return {"message": "Entry deleted"}
