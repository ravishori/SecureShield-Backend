"""scripts/otp_provider_check.py: reports configuration without ever sending, and sends exactly one dummy message per
explicitly requested target. The provider call is replaced; nothing leaves the machine."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "otp_provider_check.py"


@pytest.fixture
def run(monkeypatch):
    import app.services.otp_service as svc

    calls = []

    async def fake_deliver(identifier, code):
        calls.append((identifier, code))
        return SimpleNamespace(success=True, method="email", error=None)

    monkeypatch.setattr(svc, "deliver_otp", fake_deliver)
    spec = importlib.util.spec_from_file_location(
        "otp_provider_check_under_test", SCRIPT
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def _run(*argv):
        monkeypatch.setattr(sys, "argv", ["otp_provider_check.py", *argv])
        return mod.main(), calls

    return _run


@pytest.mark.unit
def test_offline_run_sends_nothing_and_prints_no_values(run, capsys):
    code, calls = run()
    out = capsys.readouterr().out
    assert calls == [] and code in (0, 1)
    assert "TWILIO_ACCOUNT_SID" in out and "== Result" in out
    from app.config import settings

    for secret in (
        settings.TWILIO_AUTH_TOKEN,
        settings.SMTP_PASSWORD,
        settings.SECRET_KEY,
    ):
        if secret and len(secret) > 6:
            assert secret not in out


@pytest.mark.unit
def test_each_requested_target_gets_exactly_one_dummy_message(run, capsys):
    _, calls = run(
        "--send-test-email", "me@example.org", "--send-test-sms", "+910000000000"
    )
    assert calls == [("me@example.org", "000000"), ("+910000000000", "000000")]
    assert capsys.readouterr().out.count("== Test delivery") == 1


@pytest.mark.unit
def test_a_single_target_sends_a_single_message(run):
    _, calls = run("--send-test-email", "me@example.org")
    assert calls == [("me@example.org", "000000")]
