import base64
import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict

from app.database import get_db
from app.models.user import User
from app.models.alert import Alert, AlertType, AlertSeverity
from app.routers.auth import get_current_user
from app.services.ai_gate import ai_enabled, require_enabled
from app.services.ai_limits import check_ai_rate
from app.services.alert_redaction import (
    redact_message_preview,
    redact_note,
    redact_sender,
)
from app.services.user_rate_limits import user_limit
from app.services.threat_analyzer import (
    analyze_message_signals,
    analyze_job_offer_signals,
    detect_cyberbullying,
)
from app.services.ai_service import (
    analyze_message_safety,
    analyze_job_offer_ai,
    _create_message,
)
from app.schemas.scam_verdict import ScamVerdict
from app.services.scam_verdict_adapters import (
    from_job_offer,
    from_message,
    safe_verdict,
)
from app.services.sms_header_validator import validate_sender_safe

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/message", tags=["message-analyzer"])

_ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
_MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB

_MAGIC = {
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/gif": (b"GIF87a", b"GIF89a"),
}


def _looks_like(media_type: str, data: bytes) -> bool:
    """The declared content type must match the file's real signature."""
    if media_type == "image/webp":
        return data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    return any(data.startswith(sig) for sig in _MAGIC.get(media_type, ()))


# ── Schemas ───────────────────────────────────────────────────────────────────


class MessageAnalyzeRequest(BaseModel):
    message_text: str = Field(..., min_length=1, max_length=5000)
    sender: Optional[str] = Field(None, max_length=50)
    use_ai: bool = True


class JobOfferRequest(BaseModel):
    job_text: str = Field(..., min_length=1, max_length=8000)
    use_ai: bool = True


class BullyingCheckRequest(BaseModel):
    message_text: str = Field(..., min_length=1, max_length=5000)
    reporter_note: Optional[str] = Field(None, max_length=500)


class ValidateSenderRequest(BaseModel):
    sender: str = Field(..., min_length=1, max_length=50)


class SenderValidation(BaseModel):
    is_registered: Optional[bool]
    verdict: str  # REGISTERED | UNREGISTERED | PHONE_NUMBER | UNKNOWN
    verdict_detail: str
    header: Optional[str]
    sender_id: Optional[str]
    principal_entity_name: Optional[str]
    all_entity_names: List[str]
    tsp_code: Optional[str]
    tsp_name: Optional[str]
    lsa_code: Optional[str]
    lsa_name: Optional[str]
    sender_suffix: Optional[str] = (
        None  # TRAI category letter (S/T/P) stripped to find the registered header
    )
    lookup_status: Optional[str] = (
        None  # ok | unavailable | not_applicable; 'unavailable' is NOT 'unregistered'
    )


class MessageAnalyzeResponse(BaseModel):
    is_safe: Optional[bool]
    risk_level: str
    risk_score: float
    scam_type: str
    explanation: str
    action: str
    red_flags: List[str]
    detected_patterns: List[str]
    sender_validation: Optional[SenderValidation] = None
    analyzed_at: str
    verdict: Optional[ScamVerdict] = (
        None  # additive (X-1); built from the pattern analysis, never from an AI result
    )


class JobOfferResponse(BaseModel):
    is_fake: Optional[bool]
    confidence: float
    risk_score: float
    red_flags: List[str]
    explanation: str
    action: str
    analyzed_at: str
    verdict: Optional[ScamVerdict] = (
        None  # additive (X-1); built from the pattern analysis, never from an AI result
    )


class ScreenshotExtractResponse(BaseModel):
    sender: Optional[str]
    message_text: Optional[str]
    phone_number: Optional[str]
    timestamp: Optional[str]
    extraction_note: Optional[str]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _risk_level_to_score(risk_level: str) -> float:
    mapping = {
        "safe": 0,
        "low": 20,
        "medium": 45,
        "high": 70,
        "critical": 90,
        "high_risk_scam": 90,
        "unknown": 30,
        "suspicious_message": 60,
        "potentially_suspicious": 40,
    }
    return float(mapping.get(risk_level, 0))


async def _extract_sms_from_image(
    image_bytes: bytes, media_type: str
) -> Dict[str, Any]:
    """Use Claude Vision to OCR an SMS screenshot and extract sender + message."""
    try:
        image_b64 = base64.standard_b64encode(image_bytes).decode("utf-8")

        # Async + timeout (the sync SDK call used here before blocked the whole event loop).
        response = await _create_message(
            model="claude-sonnet-4-6",
            max_tokens=600,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": image_b64,
                            },
                        },
                        {
                            "type": "text",
                            "text": (
                                "This is a screenshot of an SMS or text message. "
                                "Extract the following fields as JSON:\n"
                                "{\n"
                                '  "sender": "the sender ID or header shown at top (e.g. VK-SBIBNK, AD-HDFCBK, +91 98765 43210)",\n'
                                '  "message_text": "the full visible message body text",\n'
                                '  "phone_number": "any phone number mentioned inside the message body (if any, else null)",\n'
                                '  "timestamp": "date/time shown on the message if visible (else null)"\n'
                                "}\n\n"
                                "Rules:\n"
                                "- For sender, look at the very top of the chat screen — it may show an alphanumeric ID like VK-SBIBNK or a phone number.\n"
                                "- Extract the FULL message body text exactly as shown.\n"
                                "- If any field is not visible, use null.\n"
                                "Return ONLY valid JSON, no markdown fences, no extra text."
                            ),
                        },
                    ],
                }
            ],
        )

        raw = response.content[0].text.strip()
        # Strip any accidental markdown fences
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        data = json.loads(raw)
        return {
            "sender": data.get("sender"),
            "message_text": data.get("message_text"),
            "phone_number": data.get("phone_number"),
            "timestamp": data.get("timestamp"),
            "extraction_note": None,
        }
    except json.JSONDecodeError:
        return {
            "sender": None,
            "message_text": None,
            "phone_number": None,
            "timestamp": None,
            "extraction_note": "Could not parse extracted data. Please type the message manually.",
        }
    except Exception:
        return {
            "sender": None,
            "message_text": None,
            "phone_number": None,
            "timestamp": None,
            "extraction_note": "Screenshot analysis is unavailable right now. Please type the message manually.",
        }


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post(
    "/analyze",
    response_model=MessageAnalyzeResponse,
    # BH-1: 20/min and 200/hour per user
    dependencies=[Depends(user_limit("message_analyze"))],
)
async def analyze_message(
    request: MessageAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze an SMS or text message for scam/phishing content."""
    # Pattern-based analysis (fast)
    risk_score, threat_category, detected_patterns, msg_signals = (
        analyze_message_signals(request.message_text)
    )

    ai_result: Dict[str, Any] = {
        "is_safe": risk_score < 40,
        "risk_level": threat_category,
        "scam_type": "none",
        "explanation": f"Pattern analysis: {threat_category}",
        "action": "Be cautious with this message.",
        "red_flags": detected_patterns,
    }

    # While external AI is switched off the deterministic pattern analysis above IS the answer (not a canned "AI unavailable").
    if request.use_ai and ai_enabled():
        check_ai_rate(current_user)
        ai_result = await analyze_message_safety(request.message_text)

    combined_risk = max(
        risk_score, _risk_level_to_score(ai_result.get("risk_level", "safe"))
    )

    # Validate sender if provided
    sender_validation_data: Optional[SenderValidation] = None
    sender_verdict: Optional[str] = None
    registry_down = False
    if request.sender:
        sv = await validate_sender_safe(request.sender, db)
        registry_down = sv.get("lookup_status") == "unavailable"
        sender_verdict = str(sv.get("verdict") or "UNKNOWN")
        sender_validation_data = SenderValidation(**sv)
        # Unregistered sender boosts risk
        if sv.get("verdict") == "UNREGISTERED":
            combined_risk = min(combined_risk + 20, 100.0)
            ai_result.setdefault("red_flags", []).append(
                f"Sender '{sv['sender_id']}' is NOT in the TRAI registry — potential spoofing"
            )
        elif sv.get("verdict") == "PHONE_NUMBER":
            combined_risk = min(combined_risk + 10, 100.0)
            ai_result.setdefault("red_flags", []).append(
                "Sent from a personal phone number, not a registered business sender ID"
            )

    # Create alert if risky
    if combined_risk >= 50:
        # Redacted HERE, before persistence (1.6D-2): the stored sender and preview never hold OTPs, numbers or link values.
        stored_sender = redact_sender(request.sender)
        alert = Alert(
            user_id=current_user.id,
            alert_type=AlertType.suspicious_message,
            title="Suspicious Message Detected",
            message=(
                f"A message from {stored_sender or 'unknown sender'} was flagged as potentially dangerous. "
                f"Risk: {ai_result.get('scam_type', 'unknown')}"
            ),
            severity=AlertSeverity.critical
            if combined_risk >= 75
            else AlertSeverity.warning,
            extra_data={
                "sender": stored_sender,
                "risk_score": combined_risk,
                "scam_type": ai_result.get("scam_type"),
                "message_preview": redact_message_preview(request.message_text),
            },
        )
        if registry_down:
            # The database just failed a registry lookup. Keep the analysis we already have even if the alert cannot be saved
            # now; the failure is logged (class only) and is NOT hidden when the registry was healthy.
            try:
                db.add(alert)
                await db.commit()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "alert not saved while the sender registry is unavailable (%s)",
                    type(exc).__name__,
                )
                try:
                    await db.rollback()
                except Exception:  # noqa: BLE001
                    pass
        else:
            db.add(alert)
            await db.commit()

    all_red_flags = list(set((ai_result.get("red_flags") or []) + detected_patterns))

    return MessageAnalyzeResponse(
        is_safe=ai_result.get("is_safe"),
        risk_level=ai_result.get("risk_level", threat_category),
        risk_score=combined_risk,
        scam_type=ai_result.get("scam_type", "none"),
        explanation=ai_result.get("explanation", ""),
        action=ai_result.get("action", ""),
        red_flags=all_red_flags,
        detected_patterns=detected_patterns,
        sender_validation=sender_validation_data,
        analyzed_at=datetime.utcnow().isoformat(),
        # built from the pattern analysis only (never from an AI result) and the sender registry
        verdict=safe_verdict(
            from_message,
            pattern_score=risk_score,
            signals=msg_signals,
            sender_verdict=sender_verdict,
        ),
    )


@router.post("/extract-screenshot", response_model=ScreenshotExtractResponse)
async def extract_from_screenshot(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """
    Upload an SMS screenshot. Claude Vision will extract the sender ID,
    message text, and any phone number visible in the image.
    The extracted data can then be passed to /message/analyze for full analysis.
    """
    # Validate content type
    content_type = (file.content_type or "").lower()
    if content_type not in _ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{content_type}'. Use JPEG, PNG, or WEBP.",
        )

    # Read at most one byte past the cap so an oversized upload is never held in memory.
    image_bytes = await file.read(_MAX_IMAGE_BYTES + 1)
    if len(image_bytes) > _MAX_IMAGE_BYTES:
        raise HTTPException(
            status_code=400, detail="Image too large. Maximum size is 5 MB."
        )
    if len(image_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded.")
    if not _looks_like(content_type, image_bytes):
        raise HTTPException(
            status_code=400,
            detail="The file is not a valid image of the declared type.",
        )
    require_enabled()  # screenshot reading needs the vision provider; there is no local equivalent on the server
    check_ai_rate(current_user)

    result = await _extract_sms_from_image(image_bytes, content_type)
    return ScreenshotExtractResponse(**result)


@router.post("/validate-sender")
async def validate_sender_id(
    body: ValidateSenderRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Validate a single SMS sender ID against the TRAI registry."""
    sender = body.sender.strip()
    if not sender:
        raise HTTPException(status_code=400, detail="sender field is required")
    result = await validate_sender_safe(sender, db)
    return result


@router.post("/check-job-offer", response_model=JobOfferResponse)
async def check_job_offer(
    request: JobOfferRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze a job offer to determine if it is fraudulent."""
    risk_score, is_fake_pattern, red_flags, job_signals = analyze_job_offer_signals(
        request.job_text
    )

    ai_result: Dict[str, Any] = {
        "is_fake": is_fake_pattern,
        "confidence": int(risk_score),
        "red_flags": red_flags,
        "explanation": f"Risk score: {risk_score:.0f}/100",
        "action": "Verify the company through official channels before applying.",
    }

    if request.use_ai and ai_enabled():
        check_ai_rate(current_user)
        ai_result = await analyze_job_offer_ai(request.job_text)

    combined_risk = max(risk_score, float(ai_result.get("confidence", 0)))

    if combined_risk >= 50 or ai_result.get("is_fake"):
        alert = Alert(
            user_id=current_user.id,
            alert_type=AlertType.job_fraud,
            title="Fake Job Offer Detected",
            message=(
                f"A job offer you checked appears to be fraudulent "
                f"(confidence: {combined_risk:.0f}%). Never pay any registration fee."
            ),
            severity=AlertSeverity.warning,
            extra_data={
                "risk_score": combined_risk,
                "red_flags": ai_result.get("red_flags", []),
            },
        )
        db.add(alert)
        await db.commit()

    return JobOfferResponse(
        is_fake=ai_result.get("is_fake"),
        confidence=float(ai_result.get("confidence", combined_risk)),
        risk_score=combined_risk,
        red_flags=list(set(ai_result.get("red_flags", []) + red_flags)),
        explanation=ai_result.get("explanation", ""),
        action=ai_result.get("action", ""),
        analyzed_at=datetime.utcnow().isoformat(),
        verdict=safe_verdict(
            from_job_offer,
            pattern_score=risk_score,
            is_fake=is_fake_pattern,
            signals=job_signals,
        ),
    )


@router.post("/check-bullying")
async def check_bullying(
    request: BullyingCheckRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Detect cyberbullying in a message."""
    confidence_score, is_bullying, indicators = detect_cyberbullying(
        request.message_text
    )

    if is_bullying:
        alert = Alert(
            user_id=current_user.id,
            alert_type=AlertType.cyberbullying,
            title="Cyberbullying Detected",
            message=(
                f"A message flagged as potentially harmful content. "
                f"Confidence: {confidence_score:.0f}%. {redact_note(request.reporter_note)}"
            ),
            severity=AlertSeverity.warning,
            extra_data={
                "confidence_score": confidence_score,
                "indicators": indicators,
                "message_preview": redact_message_preview(request.message_text),
            },
        )
        db.add(alert)
        await db.commit()

    return {
        "is_bullying": is_bullying,
        "confidence_score": confidence_score,
        "indicators": indicators,
        "action_steps": [
            "Screenshot and save the message as evidence",
            "Block the sender on the platform",
            "Report to platform (WhatsApp/Instagram/etc.)",
            "If child is involved, contact school authorities",
            "File complaint at cybercrime.gov.in if severe",
        ]
        if is_bullying
        else ["No action needed — message appears safe"],
        "helpline": "Childline: 1098 | Cybercrime: 1930",
    }
