"""Guardian notifications are never dispatched where the worker is disabled (final review finding M-1).

``guardian_outbox.run_once_safe`` is what the app-monitor and elderly-protection request handlers schedule as a background task
after queuing an alert. It must honour the same switch as the periodic worker, so a development/test process can never SMS or
e-mail a guardian by default. No database and no provider is ever contacted: sessions are in-memory fakes and the send
functions are recorders.
"""

import ast
from pathlib import Path

import pytest

from app import config
from app.services import guardian_outbox as ob
from app.services import notifications

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]


class Exploding:
    def __call__(self, *a, **k):
        raise AssertionError(
            "the outbox opened a database session although guardian dispatch is disabled"
        )


@pytest.fixture
def providers(monkeypatch):
    """Recorders for the two real send functions the outbox can reach."""
    calls = []

    async def send_sms(*a, **k):
        calls.append("sms")
        return True

    async def send_email(*a, **k):
        calls.append("email")
        return True

    monkeypatch.setattr(notifications, "send_sms", send_sms)
    monkeypatch.setattr(notifications, "send_email", send_email)
    return calls


@pytest.fixture
def run_once_calls(monkeypatch):
    calls = []

    async def run_once(db, **k):
        calls.append(1)
        return {}

    monkeypatch.setattr(ob, "run_once", run_once)
    return calls


def _env(monkeypatch, environment, explicit=None):
    monkeypatch.setattr(config.settings, "ENVIRONMENT", environment)
    monkeypatch.setattr(config.settings, "GUARDIAN_WORKER_ENABLED", explicit)


@pytest.mark.parametrize("environment", ["development", "test", "staging"])
async def test_request_triggered_dispatch_is_skipped_by_default(
    monkeypatch, providers, run_once_calls, environment
):
    _env(monkeypatch, environment)
    monkeypatch.setattr("app.database.AsyncSessionLocal", Exploding())
    await ob.run_once_safe()
    assert run_once_calls == [] and providers == []


@pytest.mark.parametrize(
    "environment", ["development", "test", "staging", "production"]
)
async def test_explicit_false_disables_dispatch_everywhere(
    monkeypatch, providers, run_once_calls, environment
):
    _env(monkeypatch, environment, explicit=False)
    monkeypatch.setattr("app.database.AsyncSessionLocal", Exploding())
    await ob.run_once_safe()
    assert run_once_calls == [] and providers == []


async def test_production_default_and_explicit_opt_in_do_run(
    monkeypatch, providers, run_once_calls, no_database
):
    for environment, explicit in (
        ("production", None),
        ("development", True),
        ("test", True),
    ):
        _env(monkeypatch, environment, explicit)
        await ob.run_once_safe()
    assert run_once_calls == [1, 1, 1]
    assert providers == []  # run_once is stubbed: nothing was sent by this test


def test_unreadable_settings_count_as_dispatch_disabled(monkeypatch):
    def boom(self):
        raise RuntimeError("settings unreadable")

    monkeypatch.setattr(type(config.settings), "guardian_worker_enabled", boom)
    assert ob.dispatch_enabled() is False


async def test_worker_loop_returns_immediately_when_disabled(
    monkeypatch, run_once_calls
):
    _env(monkeypatch, "development")
    ran = []

    async def run_once_safe():
        ran.append(1)

    monkeypatch.setattr(ob, "run_once_safe", run_once_safe)
    await ob.worker_loop(0.01)  # would loop forever if it did not return
    assert ran == [] and run_once_calls == []


async def test_a_disabled_process_never_reaches_the_send_functions_end_to_end(
    monkeypatch, providers
):
    """Even with a queued, deliverable alert, the disabled gate stops before ``process`` can call SMS or e-mail."""
    _env(monkeypatch, "development")
    processed = []

    async def process(*a, **k):
        processed.append(1)
        return "sent"

    monkeypatch.setattr(ob, "process", process)
    monkeypatch.setattr("app.database.AsyncSessionLocal", Exploding())
    await ob.run_once_safe()
    assert processed == [] and providers == []


# ---- the entry points: structure that the gate relies on ----------------------------------------------------------------------
def _calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                owner = f.value.id if isinstance(f.value, ast.Name) else ""
                yield owner, f.attr, node
            elif isinstance(f, ast.Name):
                yield "", f.id, node


def _args_text(node):
    return [ast.unparse(a) for a in node.args]


@pytest.mark.parametrize("router", ["app_monitor", "elderly_protection"])
def test_request_handlers_schedule_only_the_gated_function(router):
    tree = ast.parse(
        (BACKEND / "app" / "routers" / f"{router}.py").read_text(encoding="utf-8")
    )
    scheduled = [
        a
        for owner, name, n in _calls(tree)
        if name == "add_task"
        for a in _args_text(n)
    ]
    assert "guardian_outbox.run_once_safe" in scheduled
    assert not any(
        a.startswith("guardian_outbox.") and a != "guardian_outbox.run_once_safe"
        for a in scheduled
    )
    for owner, name, node in _calls(
        tree
    ):  # and they never call the outbox's dispatching functions directly
        assert not (
            owner == "guardian_outbox"
            and name in {"run_once", "process", "worker_loop"}
        ), (router, name)


def test_the_outbox_is_the_only_guardian_code_that_sends_and_process_is_only_called_by_run_once():
    senders = []
    for path in (BACKEND / "app").rglob("*.py"):
        if (
            path.name in {"guardian_outbox.py", "guardian_alerts.py"}
            or "guardian" in path.name
        ):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if any(
                name in {"send_sms", "send_email"} for _, name, _ in _calls(tree)
            ) or "notifications.send_sms" in path.read_text(encoding="utf-8"):
                senders.append(path.name)
    assert senders == ["guardian_outbox.py"], senders
    tree = ast.parse(
        (BACKEND / "app" / "services" / "guardian_outbox.py").read_text(
            encoding="utf-8"
        )
    )
    callers = []
    for fn in [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
    ]:
        if any(
            name == "process" and owner == ""
            for owner, name, _ in _calls(ast.Module(body=fn.body, type_ignores=[]))
        ):
            callers.append(fn.name)
    assert callers == ["run_once"], callers
    src = (BACKEND / "app" / "services" / "guardian_outbox.py").read_text(
        encoding="utf-8"
    )
    assert src.index("if not dispatch_enabled():") < src.index(
        "async with AsyncSessionLocal() as db:\n            await run_once(db)"
    )


# Every function in app/ that can call notifications.send_sms / send_email. Anything NOT in this list is new and must be reviewed:
# either user-initiated by an explicit API action (and so deliberately ungated) or gated by guardian_outbox.dispatch_enabled().
KNOWN_SEND_SITES = {
    (
        "routers/elderly_protection.py",
        "guardian_verify_start",
    ),  # explicit user action: e-mail the guardian a confirmation code
    (
        "routers/elderly_protection.py",
        "_deliver_guardian_alert",
    ),  # dead legacy code, gated (test below)
    (
        "routers/alerts.py",
        "_notify_emergency_contacts",
    ),  # panic button: a safety feature, never gated
    ("routers/identity.py", "email_change_confirm"),  # explicit user action
    ("routers/reports.py", "email_daily_report"),  # explicit user action
    (
        "services/guardian_outbox.py",
        "process",
    ),  # gated through run_once_safe / worker_loop / the worker start
    ("services/identity.py", "notify_claim_released"),  # explicit user action
}


def test_every_notification_send_site_is_known():
    found = set()
    for path in (BACKEND / "app").rglob("*.py"):
        if path.name == "notifications.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            for n in ast.walk(fn):
                if (
                    isinstance(n, ast.Attribute)
                    and n.attr in {"send_sms", "send_email"}
                    and isinstance(n.value, ast.Name)
                    and n.value.id == "notifications"
                ):
                    found.add((path.relative_to(BACKEND / "app").as_posix(), fn.name))
    assert found <= KNOWN_SEND_SITES, sorted(found - KNOWN_SEND_SITES)
    assert found, "scan found nothing: the scanner is broken"


async def test_the_legacy_direct_deliverer_is_gated(monkeypatch, providers):
    from app.routers import elderly_protection as ep

    _env(monkeypatch, "development")
    result = await ep._deliver_guardian_alert(
        "Asha",
        "Guardian",
        "+910000000000",
        "g@example.com",
        "App",
        80,
        "high",
        [],
        None,
    )
    assert result == {} and providers == []
    _env(monkeypatch, "development", explicit=True)
    result = await ep._deliver_guardian_alert(
        "Asha",
        "Guardian",
        "+910000000000",
        "g@example.com",
        "App",
        80,
        "high",
        [],
        None,
    )
    assert providers == ["sms", "email"] and set(result) == {"sms", "email"}


def test_worker_default_matrix_is_off_outside_production():
    from app.config import Settings

    base = dict(
        DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
        MIGRATOR_DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
        SECRET_KEY="k",
        SMTP_HOST="h",
        SMTP_PORT="1",
        SMTP_USER="u",
        SMTP_PASSWORD="p",
        SMTP_FROM_EMAIL="e@e.c",
        ERROR_NOTIFY_EMAIL="e@e.c",
        TWILIO_ACCOUNT_SID="AC",
        TWILIO_AUTH_TOKEN="t",
        TWILIO_SMS_NUMBER="1",
        TWILIO_WHATSAPP_NUMBER="1",
    )
    got = {
        env: Settings(_env_file=None, ENVIRONMENT=env, **base).guardian_worker_enabled()
        for env in ("development", "test", "staging", "production")
    }
    assert got == {
        "development": False,
        "test": False,
        "staging": False,
        "production": True,
    }
