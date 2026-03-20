"""
SecureShield AI — Centralised Logging Service
=============================================
Writes every error / exception to THREE places simultaneously:
  1. Rotating log file  (logs/secureshield.log)
  2. PostgreSQL table   (error_logs)
  3. Email alert        (for ERROR / CRITICAL levels, via SMTP)

Usage (anywhere in the app):
    from app.services.logger_service import log_error, get_logger

    # Log an unhandled exception
    await log_error("Something broke", exc=e, endpoint="/auth/send-otp", method="POST")

    # Use as a standard Python logger (file only, synchronous)
    logger = get_logger(__name__)
    logger.info("OTP sent to +91xxxxxx")
"""

import asyncio
import logging
import logging.handlers
import os
import smtplib
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---------------------------------------------------------------------------
# Log directory & rotating file setup
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(_BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "secureshield.log")

_formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Root "secureshield" logger — all named loggers inherit from it
_root_logger = logging.getLogger("secureshield")
if not _root_logger.handlers:
    _root_logger.setLevel(logging.DEBUG)

    # Rotating file: 10 MB per file, keep 7 backups
    _fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=7, encoding="utf-8"
    )
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_formatter)
    _root_logger.addHandler(_fh)

    # Console (INFO+)
    _ch = logging.StreamHandler()
    _ch.setLevel(logging.INFO)
    _ch.setFormatter(_formatter)
    _root_logger.addHandler(_ch)

# Thread pool for fire-and-forget email (keeps async routes non-blocking)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mailer")


# ---------------------------------------------------------------------------
# Email helper (runs in thread to avoid blocking the event loop)
# ---------------------------------------------------------------------------
def _send_email_sync(subject: str, html_body: str, to_email: str) -> None:
    """Synchronous SMTP send — called from thread executor."""
    from app.config import settings

    if not to_email:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            srv.sendmail(settings.SMTP_FROM_EMAIL, to_email, msg.as_string())
        _root_logger.info(f"Error alert email sent → {to_email}")
    except Exception as e:
        _root_logger.error(f"Failed to send error alert email: {e}")


# ---------------------------------------------------------------------------
# DB helper (async, uses its own session so it never depends on request scope)
# ---------------------------------------------------------------------------
async def _log_to_db(
    *,
    level: str,
    message: str,
    exception_type: str | None,
    traceback_str: str | None,
    endpoint: str | None,
    method: str | None,
    user_id: str | None,
    client_ip: str | None,
    extra: dict | None,
) -> bool:
    """Write one row to error_logs table. Returns True on success."""
    from app.database import AsyncSessionLocal
    from app.models.error_log import ErrorLog

    try:
        async with AsyncSessionLocal() as session:
            entry = ErrorLog(
                level=level,
                logger_name="secureshield",
                message=message,
                exception_type=exception_type,
                traceback=traceback_str,
                endpoint=endpoint,
                method=method,
                user_id=user_id,
                client_ip=client_ip,
                extra=extra or {},
                email_sent=False,
            )
            session.add(entry)
            await session.commit()
        return True
    except Exception as db_err:
        # Don't re-raise — logging must never crash the app
        _root_logger.error(f"[logger_service] DB write failed: {db_err}")
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def log_error(
    message: str,
    exc: Exception | None = None,
    level: str = "ERROR",
    endpoint: str | None = None,
    method: str | None = None,
    user_id: str | None = None,
    client_ip: str | None = None,
    extra: dict | None = None,
    send_email: bool = True,
) -> None:
    """
    Central error logger. Call from any router, service, or middleware.

    Args:
        message:    Human-readable description of what went wrong.
        exc:        The caught exception (optional).
        level:      Logging level string: DEBUG / INFO / WARNING / ERROR / CRITICAL.
        endpoint:   API path, e.g. "/auth/send-otp".
        method:     HTTP verb, e.g. "POST".
        user_id:    Authenticated user ID if available.
        client_ip:  Caller's IP address.
        extra:      Any additional key-value pairs (stored as JSONB).
        send_email: Send email alert for ERROR/CRITICAL (default True).
    """
    from app.config import settings

    tb_str = traceback.format_exc() if exc else None
    if tb_str and tb_str.strip() in ("NoneType: None", ""):
        tb_str = None

    exc_type = type(exc).__name__ if exc else None
    full_message = f"{message} — {exc}" if exc else message

    # ── 1. File log ────────────────────────────────────────────────────────
    named_logger = logging.getLogger(f"secureshield.{endpoint or 'app'}")
    log_fn = getattr(named_logger, level.lower(), named_logger.error)
    log_fn(full_message)
    if tb_str:
        named_logger.debug(f"Traceback:\n{tb_str}")

    # ── 2. Database ────────────────────────────────────────────────────────
    await _log_to_db(
        level=level,
        message=full_message,
        exception_type=exc_type,
        traceback_str=tb_str,
        endpoint=endpoint,
        method=method,
        user_id=user_id,
        client_ip=client_ip,
        extra=extra,
    )

    # ── 3. Email alert (ERROR / CRITICAL only) ─────────────────────────────
    notify_email = getattr(settings, "ERROR_NOTIFY_EMAIL", "")
    if send_email and level in ("ERROR", "CRITICAL") and notify_email:
        icon = "🔴" if level == "CRITICAL" else "🟠"
        subject = f"{icon} SecureShield [{level}] {exc_type or 'Error'} @ {endpoint or 'N/A'}"
        html_body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0A0E27;color:#e0e0e0;padding:20px;">
        <div style="background:#1a1e3a;border-left:5px solid {'#ff4444' if level=='CRITICAL' else '#ff8800'};
                    padding:20px;border-radius:8px;max-width:700px;">
          <h2 style="color:{'#ff4444' if level=='CRITICAL' else '#ff8800'};">
            {icon} SecureShield AI — {level}
          </h2>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:6px;color:#aaa;width:130px;">⏰ Time (UTC)</td>
                <td style="padding:6px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr style="background:#222644;">
                <td style="padding:6px;color:#aaa;">🌐 Endpoint</td>
                <td style="padding:6px;">{method or ''} {endpoint or 'N/A'}</td></tr>
            <tr><td style="padding:6px;color:#aaa;">⚡ Error Type</td>
                <td style="padding:6px;color:#ff6666;">{exc_type or 'N/A'}</td></tr>
            <tr style="background:#222644;">
                <td style="padding:6px;color:#aaa;">💬 Message</td>
                <td style="padding:6px;">{full_message}</td></tr>
            <tr><td style="padding:6px;color:#aaa;">👤 User ID</td>
                <td style="padding:6px;">{user_id or 'Anonymous'}</td></tr>
            <tr style="background:#222644;">
                <td style="padding:6px;color:#aaa;">🌍 Client IP</td>
                <td style="padding:6px;">{client_ip or 'N/A'}</td></tr>
          </table>
          {"<h3 style='color:#aaa;'>Traceback</h3><pre style='background:#111;padding:12px;border-radius:4px;overflow-x:auto;font-size:12px;color:#ff8888;'>" + (tb_str or '') + "</pre>" if tb_str else ""}
        </div>
        </body></html>
        """
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            _executor, _send_email_sync, subject, html_body, notify_email
        )


def get_logger(name: str = "secureshield") -> logging.Logger:
    """
    Get a named logger that inherits SecureShield's file handler.
    Use for INFO/DEBUG/WARNING (not for caught exceptions — use log_error() for those).

    Example:
        logger = get_logger(__name__)
        logger.info("Processing started")
    """
    return logging.getLogger(f"secureshield.{name}")
