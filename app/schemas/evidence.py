import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.evidence import Evidence, FileType
from app.services.upload_safety import display_name


class EvidenceResponse(BaseModel):
    """Evidence metadata. The server's filesystem path is NOT exposed; use ``download_url``."""

    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    description: Optional[str]
    filename: str
    download_url: str
    file_type: FileType
    file_size_bytes: int
    is_encrypted: bool
    case_id: Optional[str]
    created_at: datetime

    @classmethod
    def from_evidence(cls, e: Evidence) -> "EvidenceResponse":
        return cls(
            id=e.id,
            user_id=e.user_id,
            title=e.title,
            description=e.description,
            filename=display_name(e.file_path),
            download_url=f"/api/v1/evidence/{e.id}/download",
            file_type=e.file_type,
            file_size_bytes=e.file_size_bytes,
            is_encrypted=e.is_encrypted,
            case_id=e.case_id,
            created_at=e.created_at,
        )
