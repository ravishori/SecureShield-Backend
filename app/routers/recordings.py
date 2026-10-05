import os
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel

from app.database import get_db
from app.config import settings
from app.models.user import User
from app.models.recording import Recording
from app.routers.auth import get_current_user
from app.services.upload_safety import (
    display_name,
    guess_media_type,
    parse_uuid_or_404,
    resolve_inside,
    save_upload,
)

router = APIRouter(prefix="/recordings", tags=["recordings"])

UPLOAD_DIR = "uploads/recordings"
os.makedirs(UPLOAD_DIR, exist_ok=True)

SHARE_LINK_TTL_HOURS = 24


# ── Schemas ───────────────────────────────────────────────────────────────────


class RecordingResponse(BaseModel):
    id: str
    title: str
    file_size_bytes: int
    duration_seconds: int
    is_encrypted: bool
    notes: Optional[str]
    share_token: Optional[str]
    share_expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_custom(cls, r: Recording) -> "RecordingResponse":
        return cls(
            id=str(r.id),
            title=r.title,
            file_size_bytes=r.file_size_bytes,
            duration_seconds=r.duration_seconds,
            is_encrypted=r.is_encrypted,
            notes=r.notes,
            share_token=r.share_token,
            share_expires_at=r.share_expires_at,
            created_at=r.created_at,
        )


class ShareLinkResponse(BaseModel):
    share_token: str
    expires_at: datetime
    share_url: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/upload", response_model=RecordingResponse)
async def upload_recording(
    title: str = Form(..., min_length=1, max_length=200),
    duration_seconds: int = Form(0, ge=0, le=86400),
    is_encrypted: bool = Form(True),
    notes: Optional[str] = Form(None, max_length=2000),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    file_path, file_size = await save_upload(
        file,
        UPLOAD_DIR,
        default_name="recording.aac",
        max_bytes=settings.MAX_RECORDING_MB * 1024 * 1024,
    )
    recording = Recording(
        user_id=current_user.id,
        title=title.strip(),
        file_path=file_path,
        file_size_bytes=file_size,
        duration_seconds=duration_seconds,
        is_encrypted=is_encrypted,
        notes=notes,
    )
    db.add(recording)
    try:
        await db.commit()
    except BaseException:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise
    await db.refresh(recording)
    return RecordingResponse.from_orm_custom(recording)


async def _owned(db: AsyncSession, user: User, recording_id: str) -> Recording:
    result = await db.execute(
        select(Recording).where(
            Recording.id == parse_uuid_or_404(recording_id, "Recording"),
            Recording.user_id == user.id,
        )
    )
    recording = result.scalar_one_or_none()
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")
    return recording


def _file_response(recording: Recording) -> FileResponse:
    path = resolve_inside(UPLOAD_DIR, recording.file_path)
    if path is None:
        raise HTTPException(status_code=404, detail="File not found on server")
    name = display_name(path)
    return FileResponse(
        path,
        media_type=guess_media_type(name),
        filename=name,
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        content_disposition_type="attachment",
    )


@router.get("/", response_model=List[RecordingResponse])
async def list_recordings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Recording)
        .where(Recording.user_id == current_user.id)
        .order_by(Recording.created_at.desc())
    )
    return [RecordingResponse.from_orm_custom(r) for r in result.scalars().all()]


@router.get("/{recording_id}/download")
async def download_recording(
    recording_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Owner-only download (the public path is the time-limited share link)."""
    return _file_response(await _owned(db, current_user, recording_id))


@router.delete("/{recording_id}")
async def delete_recording(
    recording_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    recording = await _owned(db, current_user, recording_id)
    path = resolve_inside(UPLOAD_DIR, recording.file_path)
    await db.delete(recording)
    await db.commit()
    if path:
        os.remove(path)
    return {"message": "Recording deleted"}


@router.post("/{recording_id}/share-link", response_model=ShareLinkResponse)
async def create_share_link(
    recording_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    recording = await _owned(db, current_user, recording_id)

    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=SHARE_LINK_TTL_HOURS)

    recording.share_token = token
    recording.share_expires_at = expires_at
    await db.commit()

    return ShareLinkResponse(
        share_token=token,
        expires_at=expires_at,
        share_url=f"/api/v1/recordings/share/{token}",
    )


@router.delete("/{recording_id}/share-link")
async def revoke_share_link(
    recording_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the recording's public share link immediately."""
    recording = await _owned(db, current_user, recording_id)
    recording.share_token = None
    recording.share_expires_at = None
    await db.commit()
    return {"message": "Share link revoked"}


@router.get("/share/{token}")
async def download_via_share_link(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Recording).where(Recording.share_token == token))
    recording = result.scalar_one_or_none()

    if not recording:
        raise HTTPException(status_code=404, detail="Share link not found")

    if recording.share_expires_at and datetime.utcnow() > recording.share_expires_at:
        raise HTTPException(status_code=410, detail="Share link has expired")

    return _file_response(recording)
