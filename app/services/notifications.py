"""Plain-text notifications to third parties (guardians): SMS via Twilio, e-mail via Resend/SMTP.

Same channel rules as OTP delivery (see otp_service): Resend over HTTPS is preferred because
Railway blocks outbound SMTP; SMTP is the fallback. Blocking SDKs run in worker threads. Failures
return False and log only masked identifiers and an error class, never the message body.
"""

from __future__ import annotations

import asyncio
import html
import smtplib
from email.mime.text import MIMEText

import httpx

from app.config import load_settings
from app.services import otp_service as otp
from app.services.log_scrubber import (
    mask_email_for_log,
    mask_phone_for_log,
    safe_error_text,
)
from app.services.logger_service import get_logger

logger = get_logger(__name__)


_safe_error = safe_error_text  # single shared implementation (log_scrubber)


def _send_sms_sync(phone: str, body: str) -> bool:
    s = load_settings()
    sid, token = (
        (s.TWILIO_ACCOUNT_SID or "").strip(),
        (s.TWILIO_AUTH_TOKEN or "").strip(),
    )
    sender = (s.TWILIO_SMS_NUMBER or "").strip()
    if not sid.startswith("AC") or not token or not sender:
        return False
    try:
        to = otp._normalize_phone(phone)
        from twilio.rest import Client  # type: ignore

        Client(sid, token).messages.create(body=body, from_=sender, to=to)
        logger.info(f"Notification SMS sent to {mask_phone_for_log(to)}")
        return True
    except Exception as exc:
        logger.error(
            f"Notification SMS failed to {mask_phone_for_log(phone)}: {_safe_error(exc)}"
        )
        return False


async def send_sms(phone: str, body: str) -> bool:
    return await asyncio.to_thread(_send_sms_sync, phone, body)


async def _send_email_resend(to: str, subject: str, body: str) -> bool:
    s = load_settings()
    key, sender = (s.RESEND_API_KEY or "").strip(), (s.RESEND_FROM_EMAIL or "").strip()
    if not key or not sender:
        return False
    payload = {
        "from": sender,
        "to": [to],
        "subject": subject,
        "text": body,
        "html": "<pre style='font-family:inherit'>" + html.escape(body) + "</pre>",
    }
    try:
        async with otp._http_client() as client:
            resp = await client.post(
                otp.RESEND_API_URL,
                json=payload,
                headers={"Authorization": f"Bearer {key}"},
            )
        if resp.status_code // 100 == 2:
            logger.info(
                f"Notification e-mail (resend) sent to {mask_email_for_log(to)}"
            )
            return True
        logger.error(
            f"Resend notification failed to {mask_email_for_log(to)}: HTTP {resp.status_code}"
        )
    except (httpx.HTTPError, OSError) as exc:
        logger.error(
            f"Resend notification failed to {mask_email_for_log(to)}: {_safe_error(exc)}"
        )
    return False


def _send_email_smtp_sync(to: str, subject: str, body: str) -> bool:
    from app.delivery_settings import delivery_settings

    if not delivery_settings.SMTP_FALLBACK_ENABLED:
        return False  # SMTP is switched off (SMTP_FALLBACK_ENABLED=false): Resend is the only e-mail provider
    s = load_settings()
    if not (s.SMTP_HOST or "").strip():
        return False
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"], msg["From"], msg["To"] = subject, s.SMTP_FROM_EMAIL, to
        with smtplib.SMTP(s.SMTP_HOST, s.SMTP_PORT, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(s.SMTP_USER, s.SMTP_PASSWORD.strip())
            srv.sendmail(s.SMTP_USER, to, msg.as_string())
        logger.info(f"Notification e-mail (smtp) sent to {mask_email_for_log(to)}")
        return True
    except Exception as exc:
        logger.error(
            f"SMTP notification failed to {mask_email_for_log(to)}: {_safe_error(exc)}"
        )
        return False


async def send_email(to: str, subject: str, body: str) -> bool:
    if await _send_email_resend(to, subject, body):
        return True
    return await asyncio.to_thread(_send_email_smtp_sync, to, subject, body)
