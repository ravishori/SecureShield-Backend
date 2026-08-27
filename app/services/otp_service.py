"""
OTP Delivery Service
====================
Centralised OTP delivery for SecureShield AI.

Delivery priority:
  Phone   → Twilio SMS  →  Twilio WhatsApp fallback  →  console fallback
  Email   → SMTP HTML email                           →  console fallback

Public API:
    result = await deliver_otp(identifier, code)
    result.success   # bool
    result.method    # 'sms' | 'whatsapp' | 'email' | 'console'
    result.error     # str | None — set on failure
"""

import smtplib
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import load_settings
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
    p = phone.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")

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
    method: str          # 'sms' | 'whatsapp' | 'email' | 'console'
    error: str | None = field(default=None)


# ---------------------------------------------------------------------------
# Masking helpers (keep PII out of logs)
# ---------------------------------------------------------------------------
def _mask_phone(phone: str) -> str:
    if len(phone) <= 4:
        return phone
    return phone[:3] + "*" * (len(phone) - 6) + phone[-3:]


def _mask_email(email: str) -> str:
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}*@{domain}"
    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"


# ---------------------------------------------------------------------------
# Twilio error mapping (keep raw Twilio HTML/ANSI out of logs)
# ---------------------------------------------------------------------------
def _twilio_error_message(exc: Exception) -> str:
    try:
        from twilio.base.exceptions import TwilioRestException  # type: ignore
    except ImportError:
        return str(exc).strip()

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
        hint = hints.get(exc.code, (exc.msg or str(exc)).strip())
        return f"Twilio error {exc.code}: {hint}"
    return str(exc).strip()


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
        return DeliveryResult(success=False, method="sms", error="Twilio not configured")

    try:
        from twilio.rest import Client  # type: ignore
        e164_phone = _normalize_phone(phone)
        client = Client(sid, token)
        msg = client.messages.create(
            body=f"Your SecureShield AI verification code is: {code}  Valid for 10 minutes. Do not share.",
            from_=from_number,
            to=e164_phone,
        )
        logger.info(f"Twilio SMS sent to {_mask_phone(e164_phone)} | SID: {msg.sid}")
        return DeliveryResult(success=True, method="sms")
    except ImportError:
        err = "twilio package not installed — pip install twilio"
        logger.warning(err)
        return DeliveryResult(success=False, method="sms", error=err)
    except Exception as exc:
        err = _twilio_error_message(exc)
        logger.error(f"Twilio SMS failed to {_mask_phone(phone)}: {err}")
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
        return DeliveryResult(success=False, method="whatsapp", error="Twilio not configured")

    try:
        from twilio.rest import Client  # type: ignore
        # Strip whatsapp: prefix if present, then normalise to E.164, then re-add whatsapp:
        clean_phone = phone[len("whatsapp:"):] if phone.startswith("whatsapp:") else phone
        e164_phone = _normalize_phone(clean_phone)
        client = Client(sid, token)
        msg = client.messages.create(
            body=f"Your SecureShield AI verification code is: {code}  Valid for 10 minutes. Do not share.",
            from_=from_number,
            to=f"whatsapp:{e164_phone}",
        )
        logger.info(f"WhatsApp OTP sent to {_mask_phone(e164_phone)} | SID: {msg.sid}")
        return DeliveryResult(success=True, method="whatsapp")
    except ImportError:
        err = "twilio package not installed"
        logger.warning(err)
        return DeliveryResult(success=False, method="whatsapp", error=err)
    except Exception as exc:
        err = _twilio_error_message(exc)
        logger.error(f"WhatsApp OTP failed to {_mask_phone(phone)}: {err}")
        return DeliveryResult(success=False, method="whatsapp", error=err)


# ---------------------------------------------------------------------------
# Internal: SMTP email
# ---------------------------------------------------------------------------
def _send_email(email: str, code: str) -> DeliveryResult:
    """Send OTP via SMTP with a branded dark-themed HTML email."""
    settings = load_settings()
    try:
        html = f"""
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

        logger.info(f"OTP email sent to {_mask_email(email)}")
        return DeliveryResult(success=True, method="email")

    except Exception as exc:
        err = str(exc)
        logger.error(f"SMTP email failed to {_mask_email(email)}: {err}")
        return DeliveryResult(success=False, method="email", error=err)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def deliver_otp(identifier: str, code: str) -> DeliveryResult:
    """
    Route OTP delivery to the correct channel based on identifier type.

    Phone  → SMS  → WhatsApp fallback  → console fallback
    Email  → SMTP                      → console fallback

    Always returns a DeliveryResult (never raises).
    """
    is_email = "@" in identifier

    if is_email:
        result = _send_email(identifier, code)
        if result.success:
            return result
        # Email fallback: print to console
        _console_fallback(identifier, code, "email", result.error)
        return DeliveryResult(success=False, method="console", error=result.error)

    else:
        # Try SMS first
        result = _send_sms(identifier, code)
        if result.success:
            return result

        # SMS failed — try WhatsApp
        logger.info(f"SMS failed, trying WhatsApp for {_mask_phone(identifier)}")
        result = _send_whatsapp(identifier, code)
        if result.success:
            return result

        # Both failed — console fallback
        _console_fallback(identifier, code, "sms+whatsapp", result.error)
        return DeliveryResult(success=False, method="console", error=result.error)


def _console_fallback(identifier: str, code: str, attempted_method: str, error: str | None) -> None:
    """Print OTP to console when all delivery channels fail (dev mode)."""
    masked = _mask_email(identifier) if "@" in identifier else _mask_phone(identifier)
    print(f"\n{'=' * 56}")
    print(f"  [DEV OTP]  To      : {identifier}")
    print(f"  [DEV OTP]  Masked  : {masked}")
    print(f"  [DEV OTP]  Code    : {code}")
    print(f"  [DEV OTP]  Tried   : {attempted_method}")
    if error:
        print(f"  [DEV OTP]  Error   : {error}")
    print(f"{'=' * 56}\n")
    logger.info(f"[DEV] OTP for {masked}: {code} (delivery failed: {attempted_method})")
