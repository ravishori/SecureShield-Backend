"""
Device Service
==============
Handles device registration, binding, and new-device security alerts.

Public API:
    device, is_new = await register_and_check_device(db, user, ...)
    await send_new_device_alert(user, device_name, platform, client_ip)
"""

import smtplib
import uuid
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.device import Device
from app.models.user import User
from app.services.logger_service import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Device registration / upsert
# ---------------------------------------------------------------------------
async def register_and_check_device(
    db: AsyncSession,
    user: User,
    device_token: str,
    device_name: str | None,
    platform: str | None,
    os_version: str | None,
    app_version: str | None,
    client_ip: str | None,
) -> tuple[Device, bool]:
    """
    Upsert a device record for the given user.

    Returns:
        (device, is_new_device)
        is_new_device = True  if this device_token had never been registered before
                              for this specific user.
        is_new_device = False if the device was already known.
    """
    # Check if device already exists for this user
    result = await db.execute(
        select(Device).where(
            Device.device_token == device_token,
            Device.user_id == user.id,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update last_seen and mutable fields
        existing.last_seen = datetime.utcnow()
        if device_name:
            existing.device_name = device_name
        if platform:
            existing.platform = platform
        if os_version:
            existing.os_version = os_version
        if app_version:
            existing.app_version = app_version
        existing.is_active = True
        await db.commit()
        await db.refresh(existing)
        logger.info(
            f"Device updated: user={user.id} token={device_token[:12]}*** name='{device_name}'"
        )
        return existing, False

    else:
        # New device for this user
        device = Device(
            id=uuid.uuid4(),
            user_id=user.id,
            device_token=device_token,
            device_name=device_name,
            platform=platform,
            os_version=os_version,
            app_version=app_version,
            last_seen=datetime.utcnow(),
            is_active=True,
            created_at=datetime.utcnow(),
        )
        db.add(device)
        await db.commit()
        await db.refresh(device)
        logger.info(
            f"New device registered: user={user.id} token={device_token[:12]}*** name='{device_name}' platform={platform}"
        )
        return device, True


# ---------------------------------------------------------------------------
# New-device security alert email
# ---------------------------------------------------------------------------
async def send_new_device_alert(
    user: User,
    device_name: str | None,
    platform: str | None,
    client_ip: str | None,
) -> None:
    """
    Send a branded HTML email warning the user that a new device has logged
    in to their SecureShield AI account.

    Only sends if the user has an email address on file.
    Never raises — errors are logged and swallowed.
    """
    recipient = user.email
    if not recipient:
        logger.info(
            f"Skipping new-device alert for user {user.id} — no email on file"
        )
        return

    timestamp_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    display_device = device_name or "Unknown Device"
    display_platform = platform or "Unknown Platform"
    display_ip = client_ip or "Unknown"

    html = f"""
    <html>
    <body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;
                 background-color:#0A0E27;">
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#0A0E27;padding:40px 20px;">
        <tr>
          <td align="center">
            <table width="540" cellpadding="0" cellspacing="0"
                   style="background:#1a1e3a;border-radius:16px;
                          border:1px solid rgba(255,23,68,0.3);
                          overflow:hidden;">

              <!-- Header -->
              <tr>
                <td style="background:linear-gradient(135deg,#1a0a1e,#2d0a12);
                            padding:32px 40px;text-align:center;">
                  <div style="font-size:52px;margin-bottom:8px;">&#9888;</div>
                  <h1 style="color:#FF1744;margin:0;font-size:22px;
                             letter-spacing:1px;font-weight:700;">
                    New Device Login Detected
                  </h1>
                  <p style="color:#8892b0;margin:8px 0 0;font-size:13px;">
                    SecureShield AI Security Alert
                  </p>
                </td>
              </tr>

              <!-- Body -->
              <tr>
                <td style="padding:32px 40px;">
                  <p style="color:#ccd6f6;font-size:15px;margin:0 0 24px;">
                    A new device has just signed in to your
                    <strong style="color:#00E5FF;">SecureShield AI</strong> account.
                  </p>

                  <!-- Device details table -->
                  <table width="100%" cellpadding="0" cellspacing="0"
                         style="background:#0d1130;border-radius:10px;
                                border:1px solid rgba(0,229,255,0.15);
                                overflow:hidden;margin-bottom:24px;">
                    <tr style="background:#111840;">
                      <td style="padding:10px 16px;color:#8892b0;
                                  font-size:12px;text-transform:uppercase;
                                  letter-spacing:1px;width:130px;">
                        Device
                      </td>
                      <td style="padding:10px 16px;color:#ccd6f6;font-size:14px;">
                        {display_device}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:10px 16px;color:#8892b0;
                                  font-size:12px;text-transform:uppercase;
                                  letter-spacing:1px;">
                        Platform
                      </td>
                      <td style="padding:10px 16px;color:#ccd6f6;font-size:14px;">
                        {display_platform}
                      </td>
                    </tr>
                    <tr style="background:#111840;">
                      <td style="padding:10px 16px;color:#8892b0;
                                  font-size:12px;text-transform:uppercase;
                                  letter-spacing:1px;">
                        IP Address
                      </td>
                      <td style="padding:10px 16px;color:#ccd6f6;font-size:14px;">
                        {display_ip}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:10px 16px;color:#8892b0;
                                  font-size:12px;text-transform:uppercase;
                                  letter-spacing:1px;">
                        Time
                      </td>
                      <td style="padding:10px 16px;color:#ccd6f6;font-size:14px;">
                        {timestamp_utc}
                      </td>
                    </tr>
                  </table>

                  <!-- Was this you? -->
                  <div style="background:rgba(0,229,255,0.05);
                               border:1px solid rgba(0,229,255,0.2);
                               border-radius:10px;padding:16px 20px;
                               margin-bottom:24px;">
                    <p style="color:#ccd6f6;font-size:14px;margin:0 0 8px;
                               font-weight:600;">
                      &#10003; Was this you?
                    </p>
                    <p style="color:#8892b0;font-size:13px;margin:0;">
                      If you just logged in from this device, you can safely ignore
                      this email. No action is needed.
                    </p>
                  </div>

                  <!-- Wasn't you? -->
                  <div style="background:rgba(255,23,68,0.07);
                               border:1px solid rgba(255,23,68,0.3);
                               border-radius:10px;padding:16px 20px;">
                    <p style="color:#FF1744;font-size:14px;margin:0 0 8px;
                               font-weight:600;">
                      &#9888; If this wasn't you — act immediately
                    </p>
                    <p style="color:#8892b0;font-size:13px;margin:0;">
                      Open SecureShield AI on your trusted device and log out all
                      sessions. Consider changing your phone number or email used for
                      login OTP delivery.
                    </p>
                  </div>
                </td>
              </tr>

              <!-- Footer -->
              <tr>
                <td style="padding:20px 40px 28px;
                            border-top:1px solid rgba(255,255,255,0.06);">
                  <p style="color:#3d4266;font-size:11px;
                             text-align:center;margin:0;">
                    This is an automated security notification from SecureShield AI.<br>
                    Please do not reply to this email.<br>
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

    subject = f"[Security Alert] New device login — {display_device} ({display_platform})"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = recipient
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            srv.sendmail(settings.SMTP_FROM_EMAIL, recipient, msg.as_string())

        logger.info(
            f"New-device alert sent to {recipient[:4]}***@*** "
            f"for user {user.id} | device='{display_device}'"
        )
    except Exception as exc:
        # Never propagate — security alert failure must not break the login flow
        logger.error(
            f"Failed to send new-device alert to user {user.id}: {exc}"
        )
