"""
OTP Delivery Service
====================
Centralised OTP delivery for SecureShield AI.

Delivery priority:
  Phone   → Twilio SMS  →  Twilio WhatsApp fallback
  Email   → Resend HTTPS API (if RESEND_API_KEY set)  →  SMTP HTML email fallback

Public API:
    result = await deliver_otp(identifier, code)
    result.success   # bool
    result.method    # 'sms' | 'whatsapp' | 'email' | 'none'
    result.error     # str | None — set on failure
"""

import asyncio
import smtplib
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from app.config import load_settings
from app.delivery_settings import delivery_settings
from app.services.log_scrubber import (
    mask_email_for_log,
    mask_phone_for_log,
    safe_error_text,
)
from app.services.logger_service import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Phone number normalisation → E.164
# ---------------------------------------------------------------------------
def _normalize_phone(phone: str) -> str:
    """
    Convert any phone input to E.164 format required by Twilio.

    Examples:
        9987671916      →  +919987671916  (10-digit India, adds +91)
        09987671916     →  +919987671916  (leading 0, adds +91)
        919987671916    →  +919987671916  (no +, has country code)
        +919987671916   →  +919987671916  (already correct)
        0044... / 00... →  +...           (international prefix 00 → +)
    """
    p = (
        phone.strip()
        .replace(" ", "")
        .replace("-", "")
        .replace("(", "")
        .replace(")", "")
    )

    # Already E.164
    if p.startswith("+"):
        return p

    # International dialling prefix 00xx → +xx
    if p.startswith("00"):
        return "+" + p[2:]

    # 10-digit Indian mobile (no country code, no leading 0)
    if p.isdigit() and len(p) == 10:
        return "+91" + p

    # 11-digit Indian with leading 0  (e.g. 09987671916)
    if p.isdigit() and len(p) == 11 and p.startswith("0"):
        return "+91" + p[1:]

    # Anything else — just prepend + and hope it has the country code already
    if p.isdigit():
        return "+" + p

    return p


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class DeliveryResult:
    success: bool
    method: str  # 'sms' | 'whatsapp' | 'email' | 'none'
    error: str | None = field(default=None)


# ---------------------------------------------------------------------------
# Twilio error mapping (keep raw Twilio HTML/ANSI out of logs)
# ---------------------------------------------------------------------------
def _twilio_error_message(exc: Exception) -> str:
    """Operator-facing reason for a Twilio failure. Only static hints / the numeric code are returned: Twilio's
    own message text echoes the destination number (and sometimes the body), so it is never passed on."""
    try:
        from twilio.base.exceptions import TwilioRestException  # type: ignore
    except ImportError:
        return safe_error_text(exc)

    if isinstance(exc, TwilioRestException):
        hints = {
            20003: "authentication failed — check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN",
            21211: "invalid destination phone number",
            21408: "SMS to this country is not enabled on the Twilio account",
            21608: "trial accounts can only SMS verified numbers",
            21610: "recipient has unsubscribed from this sender",
            21910: "SMS/WhatsApp channel mismatch on From/To numbers",
            30003: "destination handset unreachable",
            30007: "message filtered by carrier",
            30034: "US A2P 10DLC registration required",
            63007: "WhatsApp sender is not configured on this Twilio account",
            63015: "recipient has not joined the Twilio WhatsApp sandbox",
        }
        hint = hints.get(exc.code)
        return (
            f"Twilio error {exc.code}: {hint}" if hint else f"Twilio error {exc.code}"
        )
    return safe_error_text(exc)


# ---------------------------------------------------------------------------
# Internal: Twilio SMS
# ---------------------------------------------------------------------------
def _send_sms(phone: str, code: str) -> DeliveryResult:
    """Try Twilio SMS using plain E.164 number (TWILIO_SMS_NUMBER)."""
    settings = load_settings()
    sid = (settings.TWILIO_ACCOUNT_SID or "").strip()
    token = (settings.TWILIO_AUTH_TOKEN or "").strip()
    from_number = (settings.TWILIO_SMS_NUMBER or "").strip()

    if not sid or not token or not sid.startswith("AC") or not from_number:
        return DeliveryResult(
            success=False, method="sms", error="Twilio not configured"
        )

    try:
        from twilio.rest import Client  # type: ignore

        e164_phone = _normalize_phone(phone)
        client = Client(sid, token)
        msg = client.messages.create(
            body=f"Your SecureShield AI verification code is: {code}  Valid for 10 minutes. Do not share.",
            from_=from_number,
            to=e164_phone,
        )
        logger.info(
            f"Twilio SMS sent to {mask_phone_for_log(e164_phone)} | SID: {msg.sid}"
        )
        return DeliveryResult(success=True, method="sms")
    except ImportError:
        err = "twilio package not installed — pip install twilio"
        logger.warning(err)
        return DeliveryResult(success=False, method="sms", error=err)
    except Exception as exc:
        err = _twilio_error_message(exc)
        logger.error(f"Twilio SMS failed to {mask_phone_for_log(phone)}: {err}")
        return DeliveryResult(success=False, method="sms", error=err)


# ---------------------------------------------------------------------------
# Internal: Twilio WhatsApp fallback
# ---------------------------------------------------------------------------
def _send_whatsapp(phone: str, code: str) -> DeliveryResult:
    """Fallback: send OTP via WhatsApp sandbox."""
    settings = load_settings()
    sid = (settings.TWILIO_ACCOUNT_SID or "").strip()
    token = (settings.TWILIO_AUTH_TOKEN or "").strip()
    from_number = (settings.TWILIO_WHATSAPP_NUMBER or "").strip()
    if from_number and not from_number.startswith("whatsapp:"):
        from_number = f"whatsapp:{from_number}"

    if not sid or not token or not sid.startswith("AC") or not from_number:
        return DeliveryResult(
            success=False, method="whatsapp", error="Twilio not configured"
        )

    try:
        from twilio.rest import Client  # type: ignore

        # Strip whatsapp: prefix if present, then normalise to E.164, then re-add whatsapp:
        clean_phone = (
            phone[len("whatsapp:") :] if phone.startswith("whatsapp:") else phone
        )
        e164_phone = _normalize_phone(clean_phone)
        client = Client(sid, token)
        msg = client.messages.create(
            body=f"Your SecureShield AI verification code is: {code}  Valid for 10 minutes. Do not share.",
            from_=from_number,
            to=f"whatsapp:{e164_phone}",
        )
        logger.info(
            f"WhatsApp OTP sent to {mask_phone_for_log(e164_phone)} | SID: {msg.sid}"
        )
        return DeliveryResult(success=True, method="whatsapp")
    except ImportError:
        err = "twilio package not installed"
        logger.warning(err)
        return DeliveryResult(success=False, method="whatsapp", error=err)
    except Exception as exc:
        err = _twilio_error_message(exc)
        logger.error(f"WhatsApp OTP failed to {mask_phone_for_log(phone)}: {err}")
        return DeliveryResult(success=False, method="whatsapp", error=err)


# ---------------------------------------------------------------------------
# Internal: SMTP email
# ---------------------------------------------------------------------------
def _otp_email_html(code: str) -> str:
    return f"""
        <html>
        <body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;
                     background-color:#0A0E27;">
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#0A0E27;padding:40px 20px;">
            <tr>
              <td align="center">
                <table width="520" cellpadding="0" cellspacing="0"
                       style="background:#1a1e3a;border-radius:16px;
                              border:1px solid rgba(0,229,255,0.2);
                              overflow:hidden;">

                  <!-- Header -->
                  <tr>
                    <td style="background:linear-gradient(135deg,#1A237E,#0d1547);
                                padding:32px 40px;text-align:center;">
                      <div style="font-size:44px;margin-bottom:8px;">&#128737;</div>
                      <h1 style="color:#00E5FF;margin:0;font-size:24px;
                                 letter-spacing:1px;font-weight:700;">
                        SecureShield AI
                      </h1>
                      <p style="color:#8892b0;margin:6px 0 0;font-size:13px;">
                        Cyber Safety &amp; Threat Prevention
                      </p>
                    </td>
                  </tr>

                  <!-- Body -->
                  <tr>
                    <td style="padding:36px 40px;">
                      <p style="color:#ccd6f6;font-size:15px;margin:0 0 20px;">
                        Your one-time verification code is:
                      </p>

                      <!-- OTP box -->
                      <div style="background:#0A0E27;border:2px solid #00E5FF;
                                  border-radius:12px;text-align:center;
                                  padding:28px 20px;margin:0 0 24px;">
                        <span style="font-size:48px;font-weight:900;
                                     letter-spacing:16px;color:#00E5FF;
                                     font-family:'Courier New',monospace;">
                          {code}
                        </span>
                      </div>

                      <p style="color:#8892b0;font-size:13px;margin:0 0 8px;">
                        &#9203; Valid for <strong style="color:#ccd6f6;">10 minutes</strong>.
                      </p>
                      <p style="color:#8892b0;font-size:13px;margin:0;">
                        &#128274; Never share this code with anyone, including SecureShield support.
                      </p>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding:20px 40px 28px;
                                border-top:1px solid rgba(255,255,255,0.08);">
                      <p style="color:#3d4266;font-size:11px;
                                 text-align:center;margin:0;">
                        If you did not request this code, please ignore this email.<br>
                        &copy; 2026 SecureShield AI. All rights reserved.
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """


def _send_email(email: str, code: str) -> DeliveryResult:
    """Send OTP via SMTP with a branded dark-themed HTML email."""
    settings = load_settings()
    try:
        html = _otp_email_html(code)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{code}] Your SecureShield AI Verification Code"
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = email
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(settings.SMTP_USER, settings.SMTP_PASSWORD.strip())
            srv.sendmail(settings.SMTP_USER, email, msg.as_string())

        logger.info(f"OTP email sent to {mask_email_for_log(email)}")
        return DeliveryResult(success=True, method="email")

    except Exception as exc:
        err = safe_error_text(exc)
        logger.error(f"SMTP email failed to {mask_email_for_log(email)}: {err}")
        return DeliveryResult(success=False, method="email", error=err)


# ---------------------------------------------------------------------------
# Internal: Resend (HTTPS email API). Hosts such as Railway block outbound SMTP, so this is the
# production email path; SMTP stays as a fallback for environments that allow it.
# ---------------------------------------------------------------------------
RESEND_API_URL = "https://api.resend.com/emails"
RESEND_TIMEOUT_SECONDS = 15.0


def _http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=RESEND_TIMEOUT_SECONDS)


async def _send_email_resend(email: str, code: str) -> DeliveryResult:
    settings = load_settings()
    api_key = (settings.RESEND_API_KEY or "").strip()
    sender = (settings.RESEND_FROM_EMAIL or "").strip()
    if not api_key or not sender:
        return DeliveryResult(
            success=False, method="email", error="Resend not configured"
        )
    payload = {
        "from": sender,
        "to": [email],
        "subject": f"[{code}] Your SecureShield AI Verification Code",
        "html": _otp_email_html(code),
    }
    try:
        async with _http_client() as client:
            resp = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code // 100 == 2:
            logger.info(f"OTP email (resend) sent to {mask_email_for_log(email)}")
            return DeliveryResult(success=True, method="email")
        # The status code is enough for operators; the body may echo the recipient or the code.
        err = f"Resend HTTP {resp.status_code}"
    except Exception as exc:
        err = f"Resend request failed ({type(exc).__name__})"
    logger.error(f"Resend email failed to {mask_email_for_log(email)}: {err}")
    return DeliveryResult(success=False, method="email", error=err)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def deliver_otp(identifier: str, code: str) -> DeliveryResult:
    """
    Route OTP delivery to the correct channel based on identifier type.

    Phone  → SMS  → WhatsApp fallback
    Email  → SMTP

    On total failure the OTP is NOT logged anywhere (see _log_delivery_failure).

    Always returns a DeliveryResult (never raises).
    """
    is_email = "@" in identifier

    if is_email:
        settings = load_settings()
        result = DeliveryResult(
            success=False, method="email", error="no email provider configured"
        )
        if (settings.RESEND_API_KEY or "").strip():
            result = await _send_email_resend(identifier, code)
            if result.success:
                return result
        if (
            delivery_settings.SMTP_FALLBACK_ENABLED
            and (settings.SMTP_HOST or "").strip()
        ):
            # smtplib is blocking: keep it off the event loop.
            result = await asyncio.to_thread(_send_email, identifier, code)
            if result.success:
                return result
        _log_delivery_failure(identifier, "email", result.error)
        return DeliveryResult(success=False, method="none", error=result.error)

    else:
        # Try SMS first
        result = await asyncio.to_thread(_send_sms, identifier, code)
        if result.success:
            return result

        # SMS failed — try WhatsApp
        logger.info(f"SMS failed, trying WhatsApp for {mask_phone_for_log(identifier)}")
        result = await asyncio.to_thread(_send_whatsapp, identifier, code)
        if result.success:
            return result

        _log_delivery_failure(identifier, "sms+whatsapp", result.error)
        return DeliveryResult(success=False, method="none", error=result.error)


def _log_delivery_failure(
    identifier: str, attempted_method: str, error: str | None
) -> None:
    """Record that every delivery channel failed.

    SECURITY: never emit the OTP value (or the unmasked identifier) to stdout,
    logs or the error_logs table. Logs are retained, shipped and e-mailed, so a
    logged code would be a working credential for the account.
    """
    masked = (
        mask_email_for_log(identifier)
        if "@" in identifier
        else mask_phone_for_log(identifier)
    )
    logger.error(
        f"OTP delivery failed for {masked} (tried: {attempted_method}): {error or 'unknown error'}"
    )
