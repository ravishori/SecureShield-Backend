"""Stage 1.6D-2: SMS-analysis alerts are redacted BEFORE persistence. Synthetic data only (reserved or invalid numbers and names)."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.alert import Alert
from app.routers import message_analyzer as ma
from app.services.alert_redaction import (
    MAX_NOTE,
    MAX_PREVIEW,
    redact_message_preview,
    redact_note,
    redact_sender,
    redact_sensitive_text,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]

OTP = "482913"
ACCT = "123456789012"
PHONE = "9876543210"
CARD = "4111 1111 1111 1111"
SECRET = "SEKRET99"


@pytest.mark.parametrize(
    "text,gone,kept",
    [
        (f"Your OTP is {OTP}. Do not share it.", [OTP], ["[OTP]", "Do not share it"]),
        (f"{OTP} is your OTP for login", [OTP], ["[OTP]", "is your OTP"]),
        (f"Use {OTP} to login to your account", [OTP], ["[CODE]", "login"]),
        (f"Your verification code: {OTP}", [OTP], ["[OTP]"]),
        (f"CVV {OTP[:3]} and PIN 4821", ["4821"], ["[OTP]"]),
        (f"Your A/c No {ACCT} is blocked", [ACCT], ["[ACCOUNT]", "is blocked"]),
        (f"account number: {ACCT}", [ACCT], ["[ACCOUNT]"]),
        (f"ref {ACCT}", [ACCT], ["[NUMBER]"]),
        (f"Pay with card {CARD} now", ["4111", "1111 1111"], ["[CARD]", "now"]),
        ("Aadhaar 1234 5678 9012", ["1234 5678"], ["[AADHAAR]"]),
        (f"Call {PHONE} immediately", [PHONE], ["[PHONE ...10]", "immediately"]),
        ("Call +91 98765 43210 now", ["98765 43210"], ["[PHONE ...10]"]),
        ("Call +1 202 555 0143 now", ["202 555 0143"], ["[PHONE ...43]"]),
        ("Pay to rahul.s@okbank today", ["rahul.s@okbank"], ["[UPI ID]", "today"]),
        ("Mail bob@example.test", ["bob@example.test"], ["b***@example.test"]),
        (
            "IFSC SBIN0001234 PAN ABCDE1234F",
            ["SBIN0001234", "ABCDE1234F"],
            ["[IFSC]", "[PAN]"],
        ),
    ],
)
def test_sensitive_values_are_replaced_and_the_wording_is_kept(text, gone, kept):
    out = redact_sensitive_text(text)
    assert all(g not in out for g in gone), out
    assert all(k in out for k in kept), out


def test_urls_keep_only_the_host_as_the_phishing_indicator():
    out = redact_sensitive_text(
        f"Verify at https://evil.example/login?otp={SECRET}&u=alice#x or http://bit.ly/abc123?t={SECRET}"
    )
    assert "[link: evil.example]" in out and "[link: bit.ly]" in out
    assert SECRET not in out and "alice" not in out and "login" not in out


def test_many_sensitive_values_in_one_message_are_all_removed():
    text = f"OTP {OTP} acct {ACCT} phone {PHONE} card {CARD} mail bob@example.test link https://evil.example/x?k={SECRET} upi a.b@okbank"
    out = redact_message_preview(text * 3)  # also exercises the length cut
    for raw in (OTP, ACCT, PHONE, "4111", "bob@", SECRET, "a.b@okbank"):
        assert raw not in out, (raw, out)
    assert len(out) <= MAX_PREVIEW


def test_a_value_cannot_survive_by_straddling_the_length_limit():
    filler = (
        "word " * 19
    )  # 95 characters, so the account number would start just before the cut
    out = redact_message_preview(f"{filler}a/c {ACCT} blocked")
    assert ACCT not in out and not any(ACCT[:k] in out for k in range(6, len(ACCT) + 1))


@pytest.mark.parametrize(
    "text",
    [
        "Your parcel arrives in 5 days, win Rs 50000 prize, share your location",
        "Meeting at 14:30 on 12-11-2026, bring 3 copies",
        "A/c XX1234 debited Rs 5000.00 on 12-11-2026 balance INR 2500",  # bank-masked tail and amounts are useful, not secret
        "Update your KYC now or your account will be blocked",
        "Congratulations! Claim your reward today",
    ],
)
def test_ordinary_text_amounts_dates_and_masked_tails_are_not_redacted(text):
    assert redact_sensitive_text(text) == text


@pytest.mark.parametrize(
    "bad", [None, "", "   ", 0, 12345, [], {}, b"bytes", "\x00\x01\x02", "СВ абв"]
)
def test_missing_or_malformed_input_never_raises_and_never_returns_raw_secrets(bad):
    out = redact_sensitive_text(bad)
    assert isinstance(out, str) and "\x00" not in out
    assert redact_message_preview(bad) == out[:MAX_PREVIEW]


def test_a_huge_message_is_bounded_and_fast():
    assert len(redact_message_preview("1234567890 " * 5000)) <= MAX_PREVIEW
    assert len(redact_note("x" * 10_000)) <= MAX_NOTE


def test_redaction_is_idempotent():
    once = redact_sensitive_text(
        f"OTP {OTP} a/c {ACCT} {PHONE} bob@example.test https://e.example/x?a={SECRET}"
    )
    assert redact_sensitive_text(once) == once


def test_an_unexpected_internal_error_returns_a_placeholder_not_the_raw_text(
    monkeypatch,
):
    import app.services.alert_redaction as ar

    monkeypatch.setattr(
        ar,
        "redact_urls_in_text",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError(f"boom {OTP}")),
    )
    assert redact_sensitive_text(f"OTP {OTP}") == "[redacted]"


@pytest.mark.parametrize(
    "sender,expected",
    [
        (f"+91{PHONE}", "[PHONE ...10]"),
        (PHONE, "[PHONE ...10]"),
        ("+91 98765 43210", "[PHONE ...10]"),
        (
            "VM-SBIBNK-S",
            "VM-SBIBNK-S",
        ),  # a registry header is public and is the evidence
        ("ad-hdfcbk", "ad-hdfcbk"),
        ("bob@example.test", "b***@example.test"),
        ("   ", None),
        ("", None),
        (None, None),
        ("\x00VM-X\x1f", "VM-X"),
    ],
)
def test_sender_is_masked_only_when_it_is_personal(sender, expected):
    assert redact_sender(sender) == expected


def test_sender_is_bounded():
    assert len(redact_sender("A" * 500)) <= 50


# ---- persistence through the real router function (fake session captures what would be written) --------------------------------
class CapturingDB:
    def __init__(self):
        self.added, self.commit, self.rollback = [], AsyncMock(), AsyncMock()

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, stmt):  # registry lookup: nothing registered
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))


SENSITIVE_SCAM = (
    f"URGENT: your account {ACCT} is blocked. Share your OTP {OTP} and click https://evil.example/kyc?t={SECRET} "
    f"to verify KYC now or call {PHONE}, else lose access"
)


async def run(message=SENSITIVE_SCAM, sender=None, db=None):
    db = db or CapturingDB()
    req = ma.MessageAnalyzeRequest(message_text=message, sender=sender, use_ai=False)
    resp = await ma.analyze_message(
        req, SimpleNamespace(id="00000000-0000-0000-0000-000000000001"), db
    )
    return resp, db


@pytest.mark.asyncio
async def test_the_persisted_alert_holds_no_raw_identifiers():
    resp, db = await run(sender=f"+91{PHONE}")
    assert len(db.added) == 1 and isinstance(db.added[0], Alert)
    stored = f"{db.added[0].title} {db.added[0].message} {db.added[0].extra_data}"
    for raw in (OTP, ACCT, PHONE, SECRET, "98765"):
        assert raw not in stored, raw
    ed = db.added[0].extra_data
    assert (
        ed["sender"] == "[PHONE ...10]"
        and "[link: evil.example]" in ed["message_preview"]
        and len(ed["message_preview"]) <= MAX_PREVIEW
    )
    assert (
        "[PHONE ...10]" in db.added[0].message
    )  # the user still sees which kind of sender it was


@pytest.mark.asyncio
async def test_a_registry_sender_header_is_kept_in_the_alert_as_evidence():
    _, db = await run(sender="VM-ZZQQXX-S")
    assert (
        db.added[0].extra_data["sender"] == "VM-ZZQQXX-S"
        and "VM-ZZQQXX-S" in db.added[0].message
    )


@pytest.mark.asyncio
async def test_redaction_does_not_change_scoring_or_the_verdict():
    """Analysis runs on the RAW text; only the stored copy is redacted. So scoring equals the detector's own result."""
    from app.services.threat_analyzer import analyze_message_signals

    pattern_score, _, patterns, _ = analyze_message_signals(SENSITIVE_SCAM)
    resp, _ = await run(SENSITIVE_SCAM)
    assert resp.verdict.risk_score == int(round(pattern_score))
    assert resp.detected_patterns == patterns
    assert resp.risk_score >= pattern_score and resp.sender_validation is None
    # and the same text with a registry sender behaves as before: +20 for an unregistered header, nothing for none
    with_sender, _ = await run(SENSITIVE_SCAM, sender="VM-ZZQQXX-S")
    assert with_sender.verdict.risk_score == min(int(round(pattern_score)) + 20, 100)


@pytest.mark.asyncio
async def test_a_low_risk_message_creates_no_alert_and_stores_nothing():
    resp, db = await run("Hi, are we still meeting for lunch at 1pm?")
    assert resp.risk_score == 0 and db.added == []


@pytest.mark.asyncio
async def test_missing_and_malformed_senders_do_not_break_alert_creation():
    for sender in (None, "   ", "\x00\x01", "x" * 50):
        _, db = await run(sender=sender)
        assert len(db.added) == 1
        assert OTP not in str(db.added[0].extra_data)


@pytest.mark.asyncio
async def test_bullying_alert_redacts_preview_and_reporter_note():
    msg = f"you are worthless, nobody likes you, call {PHONE} or I will find you at a/c {ACCT}"
    req = ma.BullyingCheckRequest(
        message_text=msg, reporter_note=f"my number is {PHONE}, otp {OTP}"
    )
    db = CapturingDB()
    await ma.check_bullying(
        req, SimpleNamespace(id="00000000-0000-0000-0000-000000000001"), db
    )
    assert db.added, (
        "the bullying message did not trigger an alert, so this test has no meaning"
    )
    stored = f"{db.added[0].message} {db.added[0].extra_data}"
    for raw in (PHONE, ACCT, OTP):
        assert raw not in stored


@pytest.mark.asyncio
async def test_no_message_content_is_logged_by_the_analyzer(caplog):
    with caplog.at_level(logging.DEBUG):
        await run(sender=f"+91{PHONE}")
    for raw in (OTP, ACCT, PHONE, SECRET):
        assert raw not in caplog.text
