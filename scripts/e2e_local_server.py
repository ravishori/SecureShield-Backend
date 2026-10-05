"""LOCAL-ONLY E2E harness: real app + real (local) PostgreSQL; only outbound delivery is replaced.

Run it against a disposable local database (DATABASE_URL / MIGRATOR_DATABASE_URL pointing at a ``*_test``
database that has been migrated), then point a debug build of the Flutter app at http://10.0.2.2:8000
(the app's LAN probe finds it). OTP codes and "sent" SMS / e-mails are appended to ``e2e_outbox.log``
(git-ignored; it contains one-time codes) instead of leaving the machine. Never run this against a shared
database.
"""

import json
import os
import sys
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
OUT = os.environ.get("E2E_OUTBOX", os.path.join(ROOT, "e2e_outbox.log"))


def log(kind, **kw):
    with open(OUT, "a", encoding="utf8") as f:
        f.write(json.dumps({"kind": kind, **kw}) + "\n")


# Do not read the developer's real backend/.env (settings give .env priority over process variables and it
# holds live provider credentials): point the settings loader at a file that does not exist.
os.environ["SECURESHIELD_ENV_FILE"] = os.path.join(ROOT, ".env.e2e-does-not-exist")

# Provider credentials: inert non-empty values (settings use env_ignore_empty=True, so blanks would count
# as missing and fail validation).
for _k, _v in {
    "TWILIO_ACCOUNT_SID": "disabled-by-e2e-harness",
    "TWILIO_AUTH_TOKEN": "disabled-by-e2e-harness",
    "SMTP_HOST": "smtp.invalid",
    "SMTP_PASSWORD": "disabled-by-e2e-harness",
    "ERROR_NOTIFY_EMAIL": "e2e@example.invalid",
    "ANTHROPIC_API_KEY": "disabled-by-e2e-harness",
    "RESEND_API_KEY": "disabled-by-e2e-harness",
    "ADMIN_TOKEN": "e2e-local-admin-token",
}.items():
    os.environ[_k] = _v
# (The link scanner / AI features would still attempt real calls with these inert keys; do not exercise them
# through this harness.)

import app.services.logger_service as _ls  # noqa: E402

_ls._send_email_sync = lambda *a, **k: None
import app.routers.auth as auth  # noqa: E402
import app.services.notifications as notif  # noqa: E402


async def fake_deliver(identifier, code):
    log("otp", to=identifier, code=code)
    return SimpleNamespace(success=True, error=None, method="e2e-local")


async def fake_sms(to, body):
    log("sms", to=to, body=body)
    return True


async def fake_email(to, subject, body):
    log("email", to=to, subject=subject, body=body)
    return True


auth.deliver_otp = fake_deliver
notif.send_sms = fake_sms
notif.send_email = fake_email

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, log_level="warning")
