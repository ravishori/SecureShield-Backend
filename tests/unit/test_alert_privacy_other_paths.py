"""Stage 1.6D-3: every alert writer that handled a phone number or free text now stores it redacted. Synthetic data only."""

import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.alert import Alert
from app.routers import community_scam as cs
from app.routers import scam_calls as sc
from app.routers import wifi as wf
from app.schemas.scam_call import ScamCallReportRequest
from app.schemas.wifi_scan import WifiScanRequest

pytestmark = [pytest.mark.unit, pytest.mark.security]

USER = SimpleNamespace(id=uuid.UUID("00000000-0000-0000-0000-000000000001"))
PHONE = "9876543210"
OTP = "482913"
ACCT = "123456789012"


class DB:
    def __init__(self, count=0):
        self.added, self.count = [], count
        self.commit, self.rollback = AsyncMock(), AsyncMock()

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, stmt):
        return SimpleNamespace(scalar=lambda: self.count)

    async def refresh(self, obj):
        obj.id = obj.id or uuid.uuid4()
        obj.created_at = datetime(2026, 1, 1)
        obj.upvotes, obj.is_verified = 0, False

    def alerts(self):
        return [o for o in self.added if isinstance(o, Alert)]


def text_of(alert):
    return f"{alert.title} | {alert.message} | {alert.extra_data}"


@pytest.mark.asyncio
async def test_scam_call_alert_masks_the_caller_and_the_reason_but_not_the_blocklist_record():
    db = DB()
    req = ScamCallReportRequest(
        caller_number=f"+91{PHONE}",
        detection_reason=f"Caller claimed CBI digital arrest, asked for OTP {OTP} and a/c {ACCT}",
    )
    row = await sc.report_scam_call(req, USER, db)
    (alert,) = db.alerts()
    stored = text_of(alert)
    for raw in (PHONE, OTP, ACCT):
        assert raw not in stored, raw
    assert (
        alert.extra_data["caller_number"] == "[PHONE ...10]"
        and "[PHONE ...10]" in alert.title
    )
    assert (
        "digital arrest" in alert.message and "[OTP]" in alert.message
    )  # the evidence (script wording) is kept
    assert (
        row.caller_number == f"+91{PHONE}"
    )  # the user's own blocklist record is unchanged (needed to block the number)
    assert alert.extra_data["risk_score"] >= 50


@pytest.mark.asyncio
async def test_scam_call_alert_for_an_unusual_caller_id_never_stores_raw_text():
    db = DB()
    await sc.report_scam_call(
        ScamCallReportRequest(
            caller_number="Unknown-ID", detection_reason="digital arrest scam script"
        ),
        USER,
        db,
    )
    (alert,) = db.alerts()
    assert "Unknown-ID" in alert.title  # alphabetic caller ids are not personal data


@pytest.mark.asyncio
async def test_community_alert_masks_the_reported_number_and_keeps_the_count():
    db = DB(count=4)
    req = cs.ScamReportRequest(
        scam_type=list(cs.ScamType)[0],
        title="Fake KYC call",
        description="They asked for money",
        phone_number=f"+91{PHONE}",
    )
    await cs.report_scam(req, USER, db)
    (alert,) = db.alerts()
    assert PHONE not in text_of(alert)
    assert (
        alert.extra_data["phone"] == "[PHONE ...10]"
        and alert.extra_data["report_count"] == 5
    )
    assert "[PHONE ...10]" in alert.message and "5 times" in alert.message
    report = next(o for o in db.added if not isinstance(o, Alert))
    assert (
        report.phone_number == f"+91{PHONE}"
    )  # the community report itself is what other users look up: unchanged


@pytest.mark.asyncio
async def test_community_alert_with_no_number_does_not_fail():
    db = DB(count=4)
    req = cs.ScamReportRequest(
        scam_type=list(cs.ScamType)[0], title="t", description="d", phone_number=None
    )
    await cs.report_scam(req, USER, db)
    assert db.alerts() == []  # the alert is only created for reported numbers


@pytest.mark.asyncio
async def test_wifi_alert_masks_identifiers_in_the_network_name():
    db = DB()
    req = WifiScanRequest(
        ssid=f"Flat {PHONE} home {ACCT}",
        bssid="aa:bb:cc:dd:ee:ff",
        signal_strength=-40,
        encryption_type="OPEN",
    )
    scan = await wf.scan_wifi(req, USER, db)
    alerts = db.alerts()
    assert alerts, (
        "an open network should raise an alert, so this test has no meaning otherwise"
    )
    stored = text_of(alerts[0])
    assert PHONE not in stored and ACCT not in stored
    assert (
        scan.ssid == f"Flat {PHONE} home {ACCT}"
    )  # the scan record keeps what the user scanned


@pytest.mark.asyncio
async def test_wifi_alert_with_no_name_still_works():
    db = DB()
    await wf.scan_wifi(
        WifiScanRequest(ssid=None, encryption_type="OPEN", signal_strength=-40),
        USER,
        db,
    )
    assert all("None" not in (a.extra_data.get("ssid") or "") for a in db.alerts())


def test_no_alert_writer_stores_a_raw_phone_or_message_field():
    """Static guard: the alert constructors in these routers must not receive a request phone/number/ssid/text directly."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "app" / "routers"
    banned = re.compile(
        r'"(?:phone|caller_number|sender|ssid)":\s*request\.|\{request\.(?:phone_number|caller_number|sender|ssid)\}'
    )
    for name in (
        "scam_calls.py",
        "community_scam.py",
        "message_analyzer.py",
        "wifi.py",
    ):
        src = (root / name).read_text(encoding="utf-8")
        assert not banned.search(src), (
            f"{name} writes a raw request value into an alert"
        )
