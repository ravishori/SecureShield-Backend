"""Account erasure: remove everything a user created, keep only what must be kept.

Policy (also recorded in docs/SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md)

DELETED (rows, and files on disk where applicable)
  evidence + recordings (rows, uploaded files, share tokens), OTP rows for the user's
  e-mail/phone, devices and everything hanging off them (alerts, network activity, app and
  Wi-Fi scans), AI conversations, app-install events, behaviour events, clone reports,
  community scam reports, emergency contacts, elderly/guardian config (third-party PII),
  family members (and other users' links pointing at this user are cleared), link scans,
  scam calls, security reports, legacy OTP-vault entries, Cyber Warrior profile + application, consent records.

ANONYMISED
  error_logs.user_id -> NULL (diagnostics stay, the link to the person goes).

RETAINED (deliberately)
  * the users row as an inert tombstone: id + created_at only, every PII column NULLed,
    is_active=false. Needed so append-only audit rows keep referential integrity.
  * warrior_audit_logs (append-only moderation/security trail): ids, action, timestamps,
    structured context and the reviewer's free-text reason. Reviewer notes could in theory
    mention the applicant, so reviewers must not put personal details in them.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field

from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_conversation import AiConversation
from app.models.alert import Alert
from app.models.app_install_event import AppInstallEvent
from app.models.app_scan import AppScan
from app.models.behavior_event import BehaviorEvent
from app.models.clone_report import CloneReport
from app.models.community_scam import CommunityScamReport
from app.models.cyber_warrior import WarriorApplication, WarriorProfile
from app.models.device import Device
from app.models.elderly_config import ElderlyConfig
from app.models.emergency_contact import EmergencyContact
from app.models.error_log import ErrorLog
from app.models.evidence import Evidence
from app.models.family import FamilyMember
from app.models.link_scan import LinkScan
from app.models.network_activity import NetworkActivity
from app.models.recording import Recording
from app.models.scam_call import ScamCall
from app.models.refresh_token import RefreshTokenUse, RevokedTokenFamily
from app.models.security_report import SecurityReport
from app.models.user import OTP, User
from app.models.pending_registration import PendingRegistration
from app.models.user_consent import UserConsent
from app.models.guardian_outbox import GuardianAlertOutbox
from app.models.wifi_scan import WifiScan

RETAINED = [
    "an inert account record (id and creation date only; all personal fields cleared)",
    "append-only moderation audit entries (identifiers, actions and reviewer notes)",
]


@dataclass
class ErasureResult:
    counts: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)


async def _del(db: AsyncSession, name: str, stmt, result: ErasureResult) -> None:
    res = await db.execute(stmt)
    result.counts[name] = res.rowcount or 0


async def erase_user_data(
    db: AsyncSession,
    user: User,
    *,
    email: str | None,
    phone: str | None,
    alt_phone: str | None = None,
) -> ErasureResult:
    """Delete/anonymise all data linked to ``user`` inside the caller's transaction.

    ``email``/``phone`` must be the values captured BEFORE the user row was scrubbed (OTP rows
    are keyed by them). Does not commit; returns the file paths to remove AFTER commit."""
    uid: uuid.UUID = user.id
    result = ErasureResult()

    # files first (paths needed before the rows go)
    for model in (Evidence, Recording):
        rows = (
            (await db.execute(select(model.file_path).where(model.user_id == uid)))
            .scalars()
            .all()
        )
        result.files.extend(p for p in rows if p)

    device_ids = (
        (await db.execute(select(Device.id).where(Device.user_id == uid)))
        .scalars()
        .all()
    )
    if device_ids:
        await _del(
            db,
            "network_activities",
            delete(NetworkActivity).where(NetworkActivity.device_id.in_(device_ids)),
            result,
        )
        await _del(
            db,
            "app_scans",
            delete(AppScan).where(AppScan.device_id.in_(device_ids)),
            result,
        )
        await _del(
            db,
            "wifi_scans",
            delete(WifiScan).where(WifiScan.device_id.in_(device_ids)),
            result,
        )
        await _del(
            db,
            "alerts_by_device",
            delete(Alert).where(Alert.device_id.in_(device_ids)),
            result,
        )
    await _del(db, "alerts", delete(Alert).where(Alert.user_id == uid), result)
    await _del(db, "devices", delete(Device).where(Device.user_id == uid), result)

    for name, model in (
        ("app_scans_by_user", AppScan),
        ("wifi_scans_by_user", WifiScan),
        ("evidence", Evidence),
        ("recordings", Recording),
        ("ai_conversations", AiConversation),
        ("app_install_events", AppInstallEvent),
        ("behavior_events", BehaviorEvent),
        ("clone_reports", CloneReport),
        ("community_scam_reports", CommunityScamReport),
        ("emergency_contacts", EmergencyContact),
        ("elderly_configs", ElderlyConfig),
        ("link_scans", LinkScan),
        ("scam_calls", ScamCall),
        ("security_reports", SecurityReport),
        ("refresh_token_uses", RefreshTokenUse),
        ("revoked_token_families", RevokedTokenFamily),
    ):
        await _del(db, name, delete(model).where(model.user_id == uid), result)

    await _del(
        db,
        "family_members",
        delete(FamilyMember).where(FamilyMember.user_id == uid),
        result,
    )
    await _del(  # other people's lists that point at this account: unlink, keep their rows
        db,
        "family_links_cleared",
        update(FamilyMember)
        .where(FamilyMember.member_user_id == uid)
        .values(member_user_id=None, consent_status="declined", invited_phone=None),
        result,
    )

    await _del(
        db,
        "warrior_profiles",
        delete(WarriorProfile).where(WarriorProfile.user_id == uid),
        result,
    )
    await _del(
        db,
        "warrior_applications",
        delete(WarriorApplication).where(WarriorApplication.user_id == uid),
        result,
    )

    # guardian alert outbox (its delivery-audit rows go with it by cascade). It runs AFTER the app_install_events delete
    # above, which already cleared event_id (ON DELETE SET NULL), so the order is safe either way.
    await _del(
        db,
        "guardian_alert_outbox",
        delete(GuardianAlertOutbox).where(GuardianAlertOutbox.user_id == uid),
        result,
    )
    await _del(
        db,
        "user_consents",
        delete(UserConsent).where(UserConsent.user_id == uid),
        result,
    )

    keys = [k.lower() for k in (email,) if k] + [p for p in (phone, alt_phone) if p]
    if email:
        await _del(
            db,
            "pending_registrations",
            delete(PendingRegistration).where(
                PendingRegistration.email == email.lower()
            ),
            result,
        )
    if keys:
        await _del(
            db,
            "otps",
            delete(OTP).where((OTP.email.in_(keys)) | (OTP.phone.in_(keys))),
            result,
        )

    await _del(
        db,
        "error_logs_anonymised",
        update(ErrorLog).where(ErrorLog.user_id == str(uid)).values(user_id=None),
        result,
    )
    # legacy table without an ORM model (feature removed, table still created by migration 1)
    res = await db.execute(
        text("DELETE FROM otp_vault_entries WHERE user_id = :u"), {"u": uid}
    )
    result.counts["otp_vault_entries"] = res.rowcount or 0
    return result


def _allowed_roots() -> list[str]:
    from app.routers import evidence as ev_router
    from app.routers import recordings as rec_router

    return [
        os.path.abspath(ev_router.UPLOAD_DIR),
        os.path.abspath(rec_router.UPLOAD_DIR),
    ]


def remove_files(paths: list[str]) -> tuple[int, int]:
    """Delete uploaded files after the DB commit. Only paths inside the configured upload
    directories are touched (a tampered DB value can never delete elsewhere).
    Returns (removed, failed); already-missing files count as removed."""
    roots = _allowed_roots()
    removed = failed = 0
    for p in paths:
        full = os.path.abspath(p)
        if not any(full == r or full.startswith(r + os.sep) for r in roots):
            failed += 1
            continue
        try:
            os.remove(full)
            removed += 1
        except FileNotFoundError:
            removed += 1
        except OSError:
            failed += 1
    return removed, failed
