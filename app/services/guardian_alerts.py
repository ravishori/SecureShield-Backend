"""Shared guardian-alert rules: who may be alerted, and what the message says.

Used by BOTH entry points (the offline-first sync and the legacy ``POST /elderly/guardian-alert``) and by the outbox worker, so
eligibility and wording can never drift apart.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Optional

# Version of the guardian disclosure the user must acknowledge when authorising a guardian. Bump it when the wording changes.
GUARDIAN_NOTICE_VERSION = "2026-11-14"

SKIP_DISABLED = "elderly mode disabled or auto-alert off"
SKIP_NO_CONTACT = "no guardian contact configured"
SKIP_NOT_AUTHORISED = "guardian not authorised by the account holder"
SKIP_NOT_VERIFIED = "guardian contact not verified"
SKIP_BELOW_THRESHOLD = "risk below the alert threshold"

# stable machine codes for the audit trail / API (the human strings above are kept for the legacy endpoint's responses)
REASON_CODES = {
    SKIP_DISABLED: "disabled",
    SKIP_NO_CONTACT: "no_contact",
    SKIP_NOT_AUTHORISED: "not_authorised",
    SKIP_NOT_VERIFIED: "not_verified",
    SKIP_BELOW_THRESHOLD: "below_threshold",
}


def clean(text: str, limit: int) -> str:
    """Single line, no control characters (these values end up in an SMS / e-mail)."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()[:limit]


def is_authorised(cfg) -> bool:
    """The account holder acknowledged the CURRENT guardian disclosure and authorised this guardian."""
    return bool(
        cfg is not None
        and cfg.guardian_authorised_at is not None
        and cfg.guardian_notice_version == GUARDIAN_NOTICE_VERSION
    )


def _same(a: Optional[str], b: Optional[str]) -> bool:
    return a is not None and b is not None and a.strip().lower() == b.strip().lower()


def email_verified(cfg) -> bool:
    return bool(
        cfg is not None
        and cfg.guardian_email
        and cfg.guardian_email_verified_at is not None
        and _same(cfg.guardian_email, cfg.guardian_email_verified_value)
    )


def phone_verified(cfg) -> bool:
    return bool(
        cfg is not None
        and cfg.guardian_phone
        and cfg.guardian_phone_verified_at is not None
        and _same(cfg.guardian_phone, cfg.guardian_phone_verified_value)
    )


def deliverable_channels(cfg) -> list[str]:
    """Channels an alert may use RIGHT NOW: authorised guardian, channel verified, and the verified value still the current one."""
    if not is_authorised(cfg):
        return []
    out = []
    if phone_verified(cfg):
        out.append("sms")
    if email_verified(cfg):
        out.append("email")
    return out


def check_eligibility(cfg, risk_score: int) -> Optional[str]:
    """None when an alert may be sent, otherwise the reason it must be skipped.

    RISK RULE: ``risk_score`` must be the SERVER-calculated score (``compute_risk`` on the synced event, or the stored
    ``server_risk_score`` for the legacy endpoint). A score reported by the device is never an input: it is untrusted and is
    only stored for comparison.

    CONSENT RULE: a guardian is a third party. Nothing is sent until the account holder has authorised this guardian under the
    current disclosure AND the guardian proved control of the channel; unverified channels are never used.
    """
    if cfg is None or not cfg.enabled or not cfg.auto_alert_guardian:
        return SKIP_DISABLED
    if not (cfg.guardian_phone or cfg.guardian_email):
        return SKIP_NO_CONTACT
    if not is_authorised(cfg):
        return SKIP_NOT_AUTHORISED
    if not deliverable_channels(cfg):
        return SKIP_NOT_VERIFIED
    if risk_score < cfg.alert_threshold:
        return SKIP_BELOW_THRESHOLD
    return None


def build_message(
    *,
    user_name: str,
    guardian_name: Optional[str],
    app_name: str,
    risk_score: int,
    risk_level: str,
    risk_tags: Iterable[str],
    clone_verdict: Optional[str],
    occurred_at: Optional[datetime] = None,
) -> str:
    greeting = (
        f"Dear {clean(guardian_name, 100)}," if guardian_name else "Guardian Alert:"
    )
    tags = [clean(t, 100) for t in list(risk_tags)[:3]]
    tags_text = "; ".join(tags) if tags else "multiple risk signals detected"
    when = (
        f" (at {occurred_at.strftime('%Y-%m-%d %H:%M')} UTC)"
        if occurred_at is not None
        else ""
    )
    lines = [
        greeting,
        "",
        "SecureShield Alert",
        "",
        f"{clean(user_name, 100)} {'just installed' if occurred_at is None else 'installed'} a "
        f"{risk_level.upper()} risk app{when}: "
        f"'{clean(app_name, 100)}'",
        f"Risk score: {risk_score}/100",
        f"Reason: {tags_text}",
    ]
    if clone_verdict:
        lines.append(f"Verdict: {clean(clone_verdict, 50).replace('_', ' ').title()}")
    lines += [
        "",
        "Please check their device and help them remove it if it looks suspicious.",
        "- SecureShield AI",
    ]
    return "\n".join(lines)
