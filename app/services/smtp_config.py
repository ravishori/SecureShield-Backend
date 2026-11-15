"""Is outbound SMTP actually configured? One shared answer for every SMTP code path.

SMTP, Twilio and the Resend key are optional so the application can run (for example locally) with no mail or SMS provider. Every
SMTP sender calls ``smtp_configured`` BEFORE it builds a message or opens a connection: a partly configured server (a host but no
login, say) must never lead to a connection attempt with blank credentials. Only variable NAMES are ever reported, never values.
"""

from __future__ import annotations

from typing import Any

# SMTP_PORT is a required, validated integer in app.config.Settings and is deliberately not part of this check.
REQUIRED_SMTP_SETTINGS = ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM_EMAIL")


def missing_smtp_settings(settings: Any) -> list[str]:
    """Names of the SMTP settings that are empty or blank."""
    return [
        name
        for name in REQUIRED_SMTP_SETTINGS
        if not str(getattr(settings, name, "") or "").strip()
    ]


def smtp_configured(settings: Any) -> bool:
    """True only when host, user, password and sender are all set."""
    return not missing_smtp_settings(settings)
