"""Stage 1.6D-1: TRAI category suffixes (-S/-T/-P) and registry-lookup failure handling.

UNIT tests only: the registry is an in-memory fake and the router function is called directly. No database, no HTTP server.
"""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import OperationalError

from app.routers import message_analyzer as ma
from app.services import sms_header_validator as v

pytestmark = pytest.mark.unit

REGISTRY = {"SBIBNK": "STATE BANK OF INDIA", "HDFCBK": "HDFC BANK LIMITED"}
SCAM = "URGENT: your account is blocked. Share your OTP and click http://bit.ly/x to verify KYC now or lose access"


class FakeDB:
    """Stands in for AsyncSession: answers the registry query from a dict and records what header was looked up."""

    def __init__(self, registry=None, fail=None):
        self.registry = REGISTRY if registry is None else registry
        self.fail = fail
        self.looked_up = []
        self.added = []
        self.commit = AsyncMock()
        self.rollback = AsyncMock()

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, stmt):
        if self.fail:
            raise self.fail
        key = (
            stmt.whereclause.right.value
        )  # parameterised: the looked-up value is a bound parameter
        self.looked_up.append(key)
        rows = [
            SimpleNamespace(principal_entity_name=n)
            for h, n in self.registry.items()
            if h == key
        ]
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))


def make_db(**kw):
    return FakeDB(**kw)


# ---- F1: canonical header extraction ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "sender,header,suffix,tsp,lsa",
    [
        ("VM-SBIBNK-S", "SBIBNK", "S", "V", "M"),
        ("VM-SBIBNK-T", "SBIBNK", "T", "V", "M"),
        ("AD-HDFCBK-P", "HDFCBK", "P", "A", "D"),
        ("vm-sbibnk-s", "SBIBNK", "S", "V", "M"),
        ("  VM-SBIBNK-s  ", "SBIBNK", "S", "V", "M"),
        ("VM-SBIBNK", "SBIBNK", None, "V", "M"),  # unsuffixed: unchanged
        ("SBIBNK", "SBIBNK", None, None, None),
    ],
)
def test_parse_extracts_the_base_header_for_verified_suffixes_only(
    sender, header, suffix, tsp, lsa
):
    p = v.parse_sender_id(sender)
    assert (p["header"], p["sender_suffix"], p["tsp_code"], p["lsa_code"]) == (
        header,
        suffix,
        tsp,
        lsa,
    )


@pytest.mark.parametrize(
    "sender",
    [
        "VM-SBIBNK-X",  # unknown suffix letter
        "VM-SBIBNK-G",  # -G is deliberately not recognised until verified
        "VM-SBIBNK-SS",
        "VM-SBIBNK-",
        "VM-SBIBNK-S-S",
        "VM--S",
        "V-SBIBNK-S",  # prefix must be exactly two letters
        "VMX-SBIBNK-S",
        "VM-SBI BNK-S",
        "VM-SBIBNK-С",  # Cyrillic capital Es in the suffix position
        "VM-SBIBNK-ſ",  # long s: upper() would turn it into 'S'
        "VM-СBIBNK-S",  # Cyrillic look-alike in the header
        "ВM-SBIBNK-S",  # Cyrillic look-alike in the prefix
    ],
)
def test_unverified_or_malformed_suffix_forms_are_not_rewritten(sender):
    assert v.parse_sender_id(sender)["sender_suffix"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sender,entity",
    [
        ("VM-SBIBNK-S", "STATE BANK OF INDIA"),
        ("VM-SBIBNK-T", "STATE BANK OF INDIA"),
        ("AD-HDFCBK-P", "HDFC BANK LIMITED"),
    ],
)
async def test_suffixed_senders_are_looked_up_by_base_header_and_keep_the_original(
    sender, entity
):
    db = make_db()
    r = await v.validate_sender(sender, db)
    assert (r["verdict"], r["principal_entity_name"], r["lookup_status"]) == (
        "REGISTERED",
        entity,
        "ok",
    )
    assert (
        db.looked_up == [r["header"]] and r["sender_id"] == sender.upper()
    )  # original preserved for evidence
    assert r["sender_suffix"] == sender[-1] and f"-{sender[-1]}" in r["verdict_detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sender",
    [
        "VM-SBIBNK-X",
        "VM-SBIBNK-G",
        "VM-SBIBNK-",
        "VM-СBIBNK-S",
        "VM-SBIBNK-S-S",
        "VKSBIBNK",
    ],
)
async def test_unknown_suffixes_and_lookalikes_never_become_registered(sender):
    r = await v.validate_sender(sender, make_db())
    assert r["verdict"] == "UNREGISTERED" and r["is_registered"] is False


@pytest.mark.asyncio
async def test_existing_outcomes_are_unchanged():
    db = make_db()
    assert (await v.validate_sender("VM-SBIBNK", db))["verdict"] == "REGISTERED"
    assert (await v.validate_sender("sbibnk", db))["verdict"] == "REGISTERED"
    assert (await v.validate_sender("ZZQQXX", db))["verdict"] == "UNREGISTERED"
    assert (await v.validate_sender("   ", db))["verdict"] == "UNKNOWN"
    assert (await v.validate_sender("+919876543210", db))["verdict"] == "PHONE_NUMBER"


# ---- F3: registry failure ----------------------------------------------------------------------------------------------------------
FAILURES = [
    OperationalError(
        "select", {}, ConnectionRefusedError("SENTINEL-PW host=db.internal")
    ),
    TimeoutError("SENTINEL-PW statement timeout"),
    RuntimeError("SENTINEL-PW unexpected"),
]
FAILURE_IDS = ["db_unavailable", "timeout", "unexpected"]


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", FAILURES, ids=FAILURE_IDS)
async def test_a_failed_lookup_is_unknown_unavailable_never_unregistered(exc, caplog):
    db = make_db(fail=exc)
    with caplog.at_level(logging.WARNING):
        r = await v.validate_sender_safe("VM-SBIBNK-S", db)
    assert (r["verdict"], r["is_registered"], r["lookup_status"]) == (
        "UNKNOWN",
        None,
        "unavailable",
    )
    assert "not verified" in r["verdict_detail"]
    db.rollback.assert_awaited()
    assert type(exc).__name__ in caplog.text
    for secret in (
        "SENTINEL-PW",
        "db.internal",
        "SBIBNK",
    ):  # no credentials, hosts or sender in the log
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_a_slow_lookup_times_out_to_unavailable(monkeypatch):
    class Slow(FakeDB):
        async def execute(self, stmt):
            await asyncio.sleep(5)

    monkeypatch.setattr(v, "REGISTRY_LOOKUP_TIMEOUT_SECONDS", 0.01)
    assert (await v.validate_sender_safe("SBIBNK", Slow()))[
        "lookup_status"
    ] == "unavailable"


@pytest.mark.asyncio
async def test_cancellation_is_not_swallowed(monkeypatch):
    async def cancelled(*a, **k):
        raise asyncio.CancelledError()

    monkeypatch.setattr(v, "validate_sender", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await v.validate_sender_safe("SBIBNK", make_db())


# ---- router: pattern analysis survives, contract unchanged -----------------------------------------------------------------------
def user():
    return SimpleNamespace(id="00000000-0000-0000-0000-000000000001")


async def analyze(db, **kw):
    return await ma.analyze_message(
        ma.MessageAnalyzeRequest(message_text=SCAM, use_ai=False, **kw), user(), db
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", FAILURES, ids=FAILURE_IDS)
async def test_analysis_survives_a_registry_failure(exc):
    baseline = await analyze(make_db())  # no sender at all
    r = await analyze(make_db(fail=exc), sender="VM-SBIBNK-S")
    assert (
        r.risk_score == baseline.risk_score
        and r.detected_patterns == baseline.detected_patterns
    )
    assert (
        r.sender_validation.verdict == "UNKNOWN"
        and r.sender_validation.lookup_status == "unavailable"
    )
    assert not any(
        "TRAI registry" in f for f in r.red_flags
    )  # no unregistered warning from an outage
    assert r.verdict is not None and r.verdict.risk_score == baseline.verdict.risk_score
    assert any("could not be verified" in lim for lim in r.verdict.limitations)
    assert "sender_not_registered" not in {e.code for e in r.verdict.evidence}


@pytest.mark.asyncio
async def test_alert_write_failure_is_tolerated_only_while_the_registry_is_down():
    broken = make_db(fail=FAILURES[0])
    broken.commit = AsyncMock(side_effect=RuntimeError("down"))
    assert (
        await analyze(broken, sender="SBIBNK")
    ).sender_validation.lookup_status == "unavailable"
    healthy = make_db()
    healthy.commit = AsyncMock(side_effect=RuntimeError("down"))
    with pytest.raises(
        RuntimeError
    ):  # a serious failure with a healthy registry is NOT hidden
        await analyze(healthy, sender="SBIBNK")


@pytest.mark.asyncio
async def test_normal_registry_outcomes_and_scores_are_unchanged():
    base = (await analyze(make_db())).risk_score
    reg = await analyze(make_db(), sender="VM-SBIBNK-S")
    unreg = await analyze(make_db(), sender="VM-ZZQQXX-S")
    phone = await analyze(make_db(), sender="+919876543210")
    assert (
        reg.sender_validation.verdict == "REGISTERED" and reg.risk_score == base
    )  # no boost, but also not "safe"
    assert (
        unreg.sender_validation.verdict == "UNREGISTERED"
        and unreg.risk_score == min(base + 20, 100)
    )
    assert (
        phone.sender_validation.verdict == "PHONE_NUMBER"
        and phone.risk_score == min(base + 10, 100)
    )
    assert (
        reg.risk_level != "safe" and reg.is_safe is not True
    )  # a registered sender never proves the content is legitimate
    assert any("does not prove" in lim for lim in reg.verdict.limitations)
