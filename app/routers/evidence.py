import os
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.evidence import Evidence, FileType
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.evidence import EvidenceResponse
from app.services import file_crypto
from app.services.upload_safety import (
    display_name,
    file_download_response,
    parse_uuid_or_404,
    resolve_inside,
    save_upload,
    EVIDENCE_POLICY,
)

router = APIRouter(prefix="/evidence", tags=["evidence"])

UPLOAD_DIR = "uploads/evidence"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_file_type(filename: str) -> FileType:
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext in ("jpg", "jpeg", "png", "gif", "bmp", "webp"):
        return FileType.screenshot
    elif ext in ("mp3", "wav", "aac", "m4a", "ogg"):
        return FileType.audio
    elif ext in ("mp4", "mov", "avi", "mkv", "webm"):
        return FileType.video
    else:
        return FileType.document


async def _owned(db: AsyncSession, user: User, evidence_id: str) -> Evidence:
    result = await db.execute(
        select(Evidence).where(
            Evidence.id == parse_uuid_or_404(evidence_id, "Evidence"),
            Evidence.user_id == user.id,
        )
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.post("/upload", response_model=EvidenceResponse)
async def upload_evidence(
    title: str = Form(..., min_length=1, max_length=200),
    description: Optional[str] = Form(None, max_length=2000),
    case_id: Optional[str] = Form(None, max_length=64),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    file_path, file_size = await save_upload(
        file,
        UPLOAD_DIR,
        default_name="evidence",
        max_bytes=settings.MAX_EVIDENCE_MB * 1024 * 1024,
        policy=EVIDENCE_POLICY,
    )
    evidence = Evidence(
        user_id=current_user.id,
        title=title.strip(),
        description=description,
        file_path=file_path,
        file_type=get_file_type(file.filename or ""),
        file_size_bytes=file_size,
        case_id=case_id,
        is_encrypted=file_crypto.encryption_enabled(),
    )
    db.add(evidence)
    try:
        await db.commit()
    except BaseException:
        if os.path.exists(file_path):
            os.remove(file_path)  # no orphan file when the row could not be saved
        raise
    await db.refresh(evidence)
    return EvidenceResponse.from_evidence(evidence)


@router.get("/", response_model=List[EvidenceResponse])
async def list_evidence(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Evidence)
        .where(Evidence.user_id == current_user.id)
        .order_by(Evidence.created_at.desc())
    )
    return [EvidenceResponse.from_evidence(e) for e in result.scalars().all()]


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return EvidenceResponse.from_evidence(await _owned(db, current_user, evidence_id))


@router.get("/{evidence_id}/download")
async def download_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Owner-only file download (attachment, never rendered inline by the browser)."""
    evidence = await _owned(db, current_user, evidence_id)
    path = resolve_inside(UPLOAD_DIR, evidence.file_path)
    if path is None:
        raise HTTPException(status_code=404, detail="File not found on server")
    return file_download_response(path, display_name(path))


@router.delete("/{evidence_id}")
async def delete_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    evidence = await _owned(db, current_user, evidence_id)
    path = resolve_inside(UPLOAD_DIR, evidence.file_path)
    await db.delete(evidence)
    await db.commit()
    if path:
        os.remove(path)
    return {"message": "Evidence deleted"}
