"""Scrubber unit tests: redact credentials/PII, keep diagnostics, never raise."""

import pytest
from jose import jwt

from app.services.log_scrubber import MAX_MESSAGE, scrub_obj, scrub_text

JWT = jwt.encode({"sub": "u"}, "unit-test-signing-key-material", algorithm="HS256")


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize("secret,text", [
    (JWT, f"decode failed for {JWT}"),
    ("abcdefghij0123456789", "got Bearer abcdefghij0123456789 from client"),
    ("AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKE12345", "url https://x.googleapis.com/v4/find?key=AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKE12345"),
    ("hunter2hunter2", "login failed password=hunter2hunter2 for user"),
    ("sk-ant-api03-ABCDEFGHIJKLMNOP", "anthropic said sk-ant-api03-ABCDEFGHIJKLMNOP is invalid"),
    ("ACabcdef0123456789abcdef0123456789", "twilio account ACabcdef0123456789abcdef0123456789 failed"),
    ("s3cr3tpw", "connect postgresql://app_user:s3cr3tpw@db.internal:5432/x failed"),
    ("victim.person@example.com", "Key (email)=(victim.person@example.com) already exists."),
    ("not an email victim", "1 validation error for M\nemail\n  value is not a valid email address [input_value='not an email victim', input_type=str]"),
    ("482910", "OTP verification code 482910 mismatch"),
    ("+919876501234", "SMS to +919876501234 failed"),
    ("9876501234", "dialled 9876501234 then dropped"),
])
def test_secret_values_are_removed(secret, text):
    out = scrub_text(text)
    assert secret not in out, out


@pytest.mark.unit
def test_emails_are_masked_not_dropped():
    assert scrub_text("send to alice.smith@example.com now") == "send to a***@example.com now"


@pytest.mark.unit
@pytest.mark.parametrize("text", [
    "HTTP code: 403 from upstream",
    "Client error '403 Forbidden' for url 'https://safebrowsing.googleapis.com/v4/threatMatches:find'",
    'File "app/routers/auth.py", line 481, in verify_otp',
    "relation \"table_that_does_not_exist\" does not exist",
    "request 7f1c2e9a-1b2c-4d5e-8f90-123456789abc took 1234 ms",
    "Twilio error 20003: authentication failed",
    "KeyError: 'missing_field'",
])
def test_diagnostics_are_preserved(text):
    assert scrub_text(text) == text


@pytest.mark.unit
def test_truncation_is_bounded_and_marked():
    out = scrub_text("A" * 100_000)
    assert len(out) < MAX_MESSAGE + 100 and "truncated" in out


@pytest.mark.unit
def test_none_and_non_strings_are_safe():
    assert scrub_text(None) is None
    assert scrub_text(12345) == "12345"
    assert scrub_obj({"a": 1, "b": [None, 2.5, True]}) == {"a": 1, "b": [None, 2.5, True]}


@pytest.mark.unit
def test_scrub_obj_recurses_and_is_depth_limited():
    nested = {"k": {"j": ["call +919876501234", {"deep": "mail a.b@c.io"}]}}
    out = scrub_obj(nested)
    assert "+919876501234" not in str(out) and "a.b@c.io" not in str(out)
    deep = cur = {}
    for _ in range(30):
        cur["n"] = {}
        cur = cur["n"]
    scrub_obj(deep)  # must not recurse forever


@pytest.mark.unit
def test_pathological_input_does_not_hang_or_raise():
    import time

    evil = ("a" * 20_000) + "@" + ("b." * 5_000) + ("1" * 20_000)
    t0 = time.time()
    scrub_text(evil, 1000)
    assert time.time() - t0 < 2.0
