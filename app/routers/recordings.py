import os
import uuid
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel

from app.database import get_db
from app.models.user import User
from app.models.recording import Recording
from app.routers.auth import get_current_user

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
    title: str = Form(...),
    duration_seconds: int = Form(0),
    is_encrypted: bool = Form(True),
    notes: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    content = await file.read()
    file_size = len(content)
    file_id = str(uuid.uuid4())
    safe_name = f"{file_id}_{file.filename or 'recording.aac'}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    with open(file_path, "wb") as f:
        f.write(content)

    recording = Recording(
        user_id=current_user.id,
        title=title,
        file_path=file_path,
        file_size_bytes=file_size,
        duration_seconds=duration_seconds,
        is_encrypted=is_encrypted,
        notes=notes,
    )
    db.add(recording)
    await db.commit()
    await db.refresh(recording)
    return RecordingResponse.from_orm_custom(recording)


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


@router.delete("/{recording_id}")
async def delete_recording(
    recording_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Recording).where(
            Recording.id == uuid.UUID(recording_id),
            Recording.user_id == current_user.id,
        )
    )
    recording = result.scalar_one_or_none()
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")

    if os.path.exists(recording.file_path):
        os.remove(recording.file_path)

    await db.delete(recording)
    await db.commit()
    return {"message": "Recording deleted"}


@router.post("/{recording_id}/share-link", response_model=ShareLinkResponse)
async def create_share_link(
    recording_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Recording).where(
            Recording.id == uuid.UUID(recording_id),
            Recording.user_id == current_user.id,
        )
    )
    recording = result.scalar_one_or_none()
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")

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


@router.get("/share/{token}")
async def download_via_share_link(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Recording).where(Recording.share_token == token)
    )
    recording = result.scalar_one_or_none()

    if not recording:
        raise HTTPException(status_code=404, detail="Share link not found")

    if recording.share_expires_at and datetime.utcnow() > recording.share_expires_at:
        raise HTTPException(status_code=410, detail="Share link has expired")

    if not os.path.exists(recording.file_path):
        raise HTTPException(status_code=404, detail="File not found on server")

    return FileResponse(
        recording.file_path,
        media_type="audio/aac",
        filename=f"{recording.title}.aac",
    )
