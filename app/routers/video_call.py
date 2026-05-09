import uuid
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from app.database import get_db
from app.models.user import User
from app.models.evidence import Evidence, FileType
from app.routers.auth import get_current_user
from app.services.ai_service import generate_fir_draft

router = APIRouter(prefix="/video-call", tags=["video-call"])


class CreateRoomRequest(BaseModel):
    call_type: str = "police_report"  # police_report | evidence_recording | family_sos
    incident_type: Optional[str] = None
    notes: Optional[str] = None


class RoomResponse(BaseModel):
    room_id: str
    room_url: str
    call_type: str
    expires_at: str
    instructions: list


class FirDraftRequest(BaseModel):
    incident_type: str
    description: str
    incident_date: str
    incident_location: str
    suspect_info: Optional[str] = None
    evidence_summary: Optional[str] = None
    complainant_name: str
    complainant_phone: str
    amount_lost: Optional[str] = None


@router.post("/create-room", response_model=RoomResponse)
async def create_video_room(
    request: CreateRoomRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a secure video call room for police reporting or evidence recording.
    Uses Jitsi Meet (open source, no API key required).
    """
    room_id = f"secureshield-{uuid.uuid4().hex[:12]}"
    room_url = f"https://meet.jit.si/{room_id}"

    from datetime import timedelta
    expires_at = (datetime.utcnow() + timedelta(hours=2)).isoformat()

    instructions_map = {
        "police_report": [
            "Share this room link with the police officer",
            "The call is encrypted end-to-end via Jitsi Meet",
            "Recording will be saved to your Evidence Locker automatically",
            "Keep the FIR draft ready to share during the call",
            "After the call, use 'Generate FIR Draft' to create official paperwork",
        ],
        "evidence_recording": [
            "Start recording immediately when you open the room",
            "State the date, time, and incident clearly",
            "Show any physical evidence to the camera",
            "Recording is automatically saved to your Evidence Locker",
        ],
        "family_sos": [
            "Share this link with a trusted family member",
            "They can join from any browser — no app required",
            "Your location is shared automatically when you join",
            "Stay on the call until help arrives",
        ],
    }

    return RoomResponse(
        room_id=room_id,
        room_url=room_url,
        call_type=request.call_type,
        expires_at=expires_at,
        instructions=instructions_map.get(request.call_type, instructions_map["police_report"]),
    )


@router.post("/generate-fir")
async def generate_fir(
    request: FirDraftRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an AI-drafted FIR (First Information Report) for cybercrime."""
    result = await generate_fir_draft(
        incident_type=request.incident_type,
        description=request.description,
        incident_date=request.incident_date,
        incident_location=request.incident_location,
        suspect_info=request.suspect_info,
        evidence_summary=request.evidence_summary,
        complainant_name=request.complainant_name,
        complainant_phone=request.complainant_phone,
        amount_lost=request.amount_lost,
    )

    # Save FIR draft as evidence
    evidence = Evidence(
        user_id=current_user.id,
        title=f"FIR Draft - {request.incident_type}",
        description=f"AI-generated FIR draft for {request.incident_type} incident on {request.incident_date}",
        file_path=f"fir_drafts/{uuid.uuid4().hex}.txt",
        file_type=FileType.document,
        file_size_bytes=len(result["fir_draft"].encode()),
        is_encrypted=False,
        case_id=f"FIR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
    )
    db.add(evidence)
    await db.commit()

    return {
        **result,
        "evidence_id": str(evidence.id),
        "case_id": evidence.case_id,
        "police_stations": [
            {"name": "Cybercrime Police Station", "city": request.incident_location},
            {"name": "National Cybercrime Reporting Portal", "url": "https://cybercrime.gov.in/"},
        ],
        "helpline": "1930",
    }


@router.get("/police-contacts")
async def get_police_contacts(
    current_user: User = Depends(get_current_user),
):
    """Returns emergency police and cybercrime contacts."""
    return {
        "cybercrime_helpline": "1930",
        "women_helpline": "1091",
        "police": "100",
        "national_emergency": "112",
        "cybercrime_portal": "https://cybercrime.gov.in/",
        "contacts": [
            {"name": "National Cybercrime Reporting Portal", "url": "https://cybercrime.gov.in/", "type": "online"},
            {"name": "Cybercrime Helpline", "phone": "1930", "type": "phone"},
            {"name": "Mumbai Cybercrime Cell", "phone": "022-24164000", "type": "phone"},
            {"name": "Delhi Cybercrime Cell", "phone": "011-23490200", "type": "phone"},
            {"name": "Bengaluru Cybercrime Cell", "phone": "080-22943050", "type": "phone"},
        ],
        "what_to_bring": [
            "Government ID proof (Aadhaar/PAN)",
            "Screenshots of the scam/fraud",
            "Bank transaction details if money was lost",
            "Contact numbers of the fraudster",
            "Your FIR draft (generate from the app)",
        ],
    }
