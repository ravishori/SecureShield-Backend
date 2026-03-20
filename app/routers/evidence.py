import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.database import get_db
from app.models.user import User
from app.models.evidence import Evidence, FileType
from app.schemas.evidence import EvidenceResponse
from app.routers.auth import get_current_user

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


@router.post("/upload", response_model=EvidenceResponse)
async def upload_evidence(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    case_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    content = await file.read()
    file_size = len(content)
    file_id = str(uuid.uuid4())
    safe_name = f"{file_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    with open(file_path, "wb") as f:
        f.write(content)

    file_type = get_file_type(file.filename or "")

    evidence = Evidence(
        user_id=current_user.id,
        title=title,
        description=description,
        file_path=file_path,
        file_type=file_type,
        file_size_bytes=file_size,
        case_id=case_id,
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)
    return evidence


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
    return result.scalars().all()


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Evidence).where(
            Evidence.id == uuid.UUID(evidence_id),
            Evidence.user_id == current_user.id,
        )
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.delete("/{evidence_id}")
async def delete_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Evidence).where(
            Evidence.id == uuid.UUID(evidence_id),
            Evidence.user_id == current_user.id,
        )
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    if os.path.exists(evidence.file_path):
        os.remove(evidence.file_path)

    await db.delete(evidence)
    await db.commit()
    return {"message": "Evidence deleted"}
