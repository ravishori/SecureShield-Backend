import logging
import json
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional

from app.database import get_db
from app.models.user import User
from app.models.evidence import Evidence, FileType
from app.routers.auth import get_current_user
from app.services.ai_limits import check_ai_rate
from app.services.upload_safety import save_text
from app.services.ai_service import generate_fir_draft, stream_fir_draft

logger = logging.getLogger(__name__)
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
    incident_type: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=4000)
    incident_date: str = Field(..., min_length=1, max_length=50)
    incident_location: str = Field(..., min_length=1, max_length=200)
    suspect_info: Optional[str] = Field(None, max_length=1000)
    evidence_summary: Optional[str] = Field(None, max_length=2000)
    complainant_name: str = Field(..., min_length=1, max_length=150)
    complainant_phone: str = Field(..., min_length=3, max_length=30)
    amount_lost: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(
        "en", max_length=8, pattern=r"^[A-Za-z]{2,3}(-[A-Za-z]{2,4})?$"
    )


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
        instructions=instructions_map.get(
            request.call_type, instructions_map["police_report"]
        ),
    )


@router.post("/generate-fir")
async def generate_fir(
    request: FirDraftRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an AI-drafted FIR (First Information Report) for cybercrime."""
    check_ai_rate(current_user)
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
        language=request.language or "en",
    )

    # Save FIR draft as evidence
    # The draft is stored as a real file (it used to be a row pointing at a file that never existed).
    from app.routers.evidence import UPLOAD_DIR as EVIDENCE_DIR

    fir_path, fir_size = save_text(
        EVIDENCE_DIR, result["fir_draft"], name="fir_draft.txt"
    )
    evidence = Evidence(
        user_id=current_user.id,
        title=f"FIR Draft - {request.incident_type}",
        description=f"AI-generated FIR draft for {request.incident_type} incident on {request.incident_date}",
        file_path=fir_path,
        file_type=FileType.document,
        file_size_bytes=fir_size,
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
            {
                "name": "National Cybercrime Reporting Portal",
                "url": "https://cybercrime.gov.in/",
            },
        ],
        "helpline": "1930",
    }


@router.post("/generate-fir-stream")
async def generate_fir_streaming(
    request: FirDraftRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stream a FIR draft as Server-Sent Events.

    The response is `text/event-stream`. Each event has the form:

        data: {"delta": "<chunk of FIR text>"}\\n\\n
        data: {"delta": "<chunk>"}\\n\\n
        ...
        data: {"done": true, "case_id": "FIR-...", "evidence_id": "uuid",
               "fir_draft": "<full text>"}\\n\\n

    On unrecoverable failure the final event includes "error": "<reason>"
    alongside a locally-generated fallback FIR (so the UI always has
    something to render).
    """
    # Build a stable case_id + evidence row UP FRONT so the client can
    # display them as soon as the first chunk arrives. The evidence row
    # is committed only after the stream finishes successfully.
    check_ai_rate(current_user)
    case_id = (
        f"FIR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    )

    async def event_stream():
        full_text_parts: list[str] = []
        had_error = False
        last_note = "This is a draft. Review with a legal expert before filing at police station."

        # First event: tell the client the case_id so it can render the
        # header immediately, before any FIR text arrives.
        yield ("data: " + json.dumps({"case_id": case_id, "started": True}) + "\n\n")

        try:
            async for event in stream_fir_draft(
                incident_type=request.incident_type,
                description=request.description,
                incident_date=request.incident_date,
                incident_location=request.incident_location,
                suspect_info=request.suspect_info,
                evidence_summary=request.evidence_summary,
                complainant_name=request.complainant_name,
                complainant_phone=request.complainant_phone,
                amount_lost=request.amount_lost,
                language=request.language or "en",
            ):
                # Forward delta + done events verbatim
                if "delta" in event:
                    full_text_parts.append(event["delta"])
                if "error" in event:
                    had_error = True
                if "note" in event:
                    last_note = event["note"]
                # Use a heartbeat-friendly small frame
                yield "data: " + json.dumps(event) + "\n\n"

        except Exception as e:
            had_error = True
            # Exception text is NOT sent to the client (it can carry internals/URLs/keys); the type
            # is logged for operators.
            logger.error("[FIR-stream] failed: %s", type(e).__name__)
            yield (
                "data: "
                + json.dumps(
                    {
                        "error": "stream_failed",
                        "done": True,
                        "fir_draft": "".join(full_text_parts) or "(no content)",
                        "note": "The draft could not be completed. Review what was generated and add any missing details.",
                    }
                )
                + "\n\n"
            )

        # Persist evidence row (best effort — never let DB write break the
        # stream after the user has already received content).
        full_text = "".join(full_text_parts) or "(empty)"
        try:
            from app.routers.evidence import UPLOAD_DIR as EVIDENCE_DIR

            fir_path, fir_size = save_text(
                EVIDENCE_DIR, full_text, name="fir_draft.txt"
            )
            evidence = Evidence(
                user_id=current_user.id,
                title=f"FIR Draft - {request.incident_type}",
                description=f"AI-generated FIR draft for {request.incident_type} incident on {request.incident_date}",
                file_path=fir_path,
                file_type=FileType.document,
                file_size_bytes=fir_size,
                is_encrypted=False,
                case_id=case_id,
            )
            db.add(evidence)
            await db.commit()
            evidence_id = str(evidence.id)
        except Exception as e:
            # Logged but not fatal — client already has the FIR text.
            evidence_id = None
            logger.error("[FIR-stream] evidence save failed: %s", type(e).__name__)
            last_note = f"{last_note} (Note: the draft could not be saved to your Evidence Locker.)"

        # Final summary event with the persisted IDs.
        yield (
            "data: "
            + json.dumps(
                {
                    "complete": True,
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "note": last_note,
                    "had_error": had_error,
                }
            )
            + "\n\n"
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            # Disable proxy/CDN buffering so chunks reach the client instantly.
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


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
            {
                "name": "National Cybercrime Reporting Portal",
                "url": "https://cybercrime.gov.in/",
                "type": "online",
            },
            {"name": "Cybercrime Helpline", "phone": "1930", "type": "phone"},
            {
                "name": "Mumbai Cybercrime Cell",
                "phone": "022-24164000",
                "type": "phone",
            },
            {"name": "Delhi Cybercrime Cell", "phone": "011-23490200", "type": "phone"},
            {
                "name": "Bengaluru Cybercrime Cell",
                "phone": "080-22943050",
                "type": "phone",
            },
        ],
        "what_to_bring": [
            "Government ID proof (Aadhaar/PAN)",
            "Screenshots of the scam/fraud",
            "Bank transaction details if money was lost",
            "Contact numbers of the fraudster",
            "Your FIR draft (generate from the app)",
        ],
    }
