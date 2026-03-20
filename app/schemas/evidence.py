from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime
from app.models.evidence import FileType


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    description: Optional[str]
    file_path: str
    file_type: FileType
    file_size_bytes: int
    is_encrypted: bool
    case_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
