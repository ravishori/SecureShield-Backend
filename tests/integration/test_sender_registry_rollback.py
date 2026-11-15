"""Stage 1.6D-1A: sender suffix parsing and registry failure handling against a REAL PostgreSQL, inside one rolled-back transaction.

Deliberately does NOT use the integration harness fixtures (``migrated_database``, ``db_engine``): that harness runs ``alembic
upgrade head`` and TRUNCATEs every table. This module:

* needs ``TEST_DATABASE_URL`` in the process environment (otherwise the tests are skipped by tests/integration/conftest.py);
* refuses unless the URL is loopback, port 5432 and the database is exactly ``secureshield_test``, and then confirms it again with
  ``SELECT current_database()`` before touching anything;
* never migrates, truncates, deletes or drops: every write happens inside ONE outer transaction that is rolled back at the end,
  and the per-table row counts and Alembic revision are compared before and after;
* never prints the URL or any credential.

The three registry fixture rows use made-up headers (RBTST1..3) so the tests do not depend on, or disturb, any seeded data.
"""

import os
import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.alert import Alert
from app.models.sms_sender_registry import SmsSenderRegistry
from app.models.user import User
from app.routers import message_analyzer as ma
from app.services import sms_header_validator as v

pytestmark = pytest.mark.integration

EXPECTED_DB = "secureshield_test"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
FIXTURE_ROWS = [
    ("RBTST1", "ROLLBACK FIXTURE BANK ONE"),
    ("RBTST2", "ROLLBACK FIXTURE BANK TWO"),
    ("RBTST3", "ROLLBACK FIXTURE BANK THREE"),
]
SCAM = "URGENT: your account is blocked. Share your OTP and click http://bit.ly/x to verify KYC now or lose access"  # pattern score 70
BENIGN = "Hi, are we still meeting for lunch at 1pm?"  # pattern score 0


def _target_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL", "").strip()
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    from app.db_identity import DatabaseIdentityError, parse_endpoint

    try:
        ep = parse_endpoint(url)
    except DatabaseIdentityError as exc:
        pytest.fail(f"refusing: TEST_DATABASE_URL failed the identity check: {exc}")
    assert ep.host in LOOPBACK, "refusing: the test database host is not loopback"
    assert (ep.port or 5432) == 5432, "refusing: the test database port is not 5432"
    assert ep.database == EXPECTED_DB, (
        f"refusing: database name must be exactly {EXPECTED_DB}"
    )
    return url


async def _counts(conn) -> dict:
    tables = [
        r[0]
        for r in await conn.execute(
            text("select tablename from pg_tables where schemaname='public' order by 1")
        )
    ]
    return {
        t: (await conn.execute(text(f'select count(*) from "{t}"'))).scalar_one()
        for t in tables
    }


class Ctx(SimpleNamespace):
    pass


@pytest_asyncio.fixture
async def ctx():
    url = _target_url()
    engine = create_async_engine(url, poolclass=NullPool)
    async with engine.connect() as conn:
        # --- identity, read-only, before anything else ---
        assert (
            await conn.execute(text("select current_database()"))
        ).scalar_one() == EXPECTED_DB
        assert (
            await conn.execute(text("select inet_server_port()"))
        ).scalar_one() == 5432
        revision = (
            await conn.execute(text("select version_num from alembic_version"))
        ).scalar_one()
        await conn.rollback()  # end the implicit read transaction; the one explicit transaction starts below
        before = await _counts(conn)
        await conn.rollback()

        trans = await conn.begin()
        try:
            user_id = uuid.uuid4()
            await conn.execute(
                sa.insert(User).values(
                    id=user_id, email=f"rollback-{user_id.hex[:8]}@example.invalid"
                )
            )
            for header, entity in FIXTURE_ROWS:
                await conn.execute(
                    sa.insert(SmsSenderRegistry).values(
                        header=header, principal_entity_name=entity
                    )
                )
            # The session joins the outer transaction through a SAVEPOINT: its commit() releases the savepoint and its
            # rollback() (used by the failure handler) rolls back to it, so the fixture rows above are never lost.
            session = AsyncSession(
                bind=conn,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            yield Ctx(
                conn=conn,
                session=session,
                user=SimpleNamespace(id=user_id),
                revision=revision,
                before=before,
            )
            await session.close()
        finally:
            await trans.rollback()

        # --- cleanup verification ---
        after = await _counts(conn)
        assert after == before, {
            t: (before[t], after[t]) for t in before if before[t] != after[t]
        }
        assert (
            await conn.execute(text("select version_num from alembic_version"))
        ).scalar_one() == revision
        assert (
            await conn.execute(
                text("select count(*) from sms_sender_registry where header = any(:h)"),
                {"h": [h for h, _ in FIXTURE_ROWS]},
            )
        ).scalar_one() == 0
        await conn.rollback()
    await engine.dispose()


async def analyze(ctx, text_=SCAM, sender=None):
    req = ma.MessageAnalyzeRequest(message_text=text_, sender=sender, use_ai=False)
    return await ma.analyze_message(req, ctx.user, ctx.session)


async def alert_count(ctx) -> int:
    return (
        await ctx.conn.execute(sa.select(sa.func.count()).select_from(Alert))
    ).scalar_one()


# ---- database identity -----------------------------------------------------------------------------------------------------------
async def test_target_identity_is_the_isolated_test_database(ctx):
    assert (
        await ctx.conn.execute(text("select current_database()"))
    ).scalar_one() == EXPECTED_DB
    assert (
        await ctx.conn.execute(text("select inet_server_port()"))
    ).scalar_one() == 5432
    assert ctx.revision  # read-only revision was readable
    assert (
        await ctx.conn.execute(
            text("select count(*) from sms_sender_registry where header = any(:h)"),
            {"h": [h for h, _ in FIXTURE_ROWS]},
        )
    ).scalar_one() == 3


# ---- F1: suffixes through the real query -----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "sender,entity",
    [
        ("VM-RBTST1-S", "ROLLBACK FIXTURE BANK ONE"),
        ("VM-RBTST1-T", "ROLLBACK FIXTURE BANK ONE"),
        ("AD-RBTST2-P", "ROLLBACK FIXTURE BANK TWO"),
        ("vm-rbtst3-s", "ROLLBACK FIXTURE BANK THREE"),
        ("VM-RBTST1", "ROLLBACK FIXTURE BANK ONE"),
    ],
)
async def test_registered_suffixed_senders_resolve_through_postgres(
    ctx, sender, entity
):
    r = await v.validate_sender_safe(sender, ctx.session)
    assert (r["verdict"], r["principal_entity_name"], r["lookup_status"]) == (
        "REGISTERED",
        entity,
        "ok",
    )


@pytest.mark.parametrize(
    "sender", ["VM-RBTST1-X", "VM-RBTST1-G", "VM-NOSUCH-S", "ZZQQXX", "VM-RBTST1-S-S"]
)
async def test_unknown_suffix_and_unregistered_senders_are_unregistered(ctx, sender):
    r = await v.validate_sender_safe(sender, ctx.session)
    assert (r["verdict"], r["lookup_status"]) == ("UNREGISTERED", "ok")


async def test_blank_and_phone_senders_need_no_lookup(ctx):
    assert (await v.validate_sender_safe("   ", ctx.session))["verdict"] == "UNKNOWN"
    phone = await v.validate_sender_safe("+919876543210", ctx.session)
    assert (phone["verdict"], phone["lookup_status"]) == (
        "PHONE_NUMBER",
        "not_applicable",
    )


# ---- healthy registry: existing scoring unchanged --------------------------------------------------------------------------------
async def test_healthy_registry_scoring_is_unchanged(ctx):
    base = await analyze(ctx, BENIGN)
    reg = await analyze(ctx, BENIGN, "VM-RBTST1-S")
    unreg = await analyze(ctx, BENIGN, "VM-NOSUCH-S")
    phone = await analyze(ctx, BENIGN, "+919876543210")
    assert base.risk_score == 0 and base.sender_validation is None
    assert (reg.sender_validation.verdict, reg.risk_score) == ("REGISTERED", 0)
    assert (unreg.sender_validation.verdict, unreg.risk_score) == ("UNREGISTERED", 20)
    assert (phone.sender_validation.verdict, phone.risk_score) == ("PHONE_NUMBER", 10)
    assert any("TRAI registry" in f for f in unreg.red_flags)
    assert not any("TRAI registry" in f for f in reg.red_flags)
    assert any(
        "does not prove" in lim for lim in reg.verdict.limitations
    )  # registered is never proof the message is genuine
    assert reg.is_safe is not None and reg.verdict.risk_score == reg.risk_score


# ---- F3: a REAL PostgreSQL failure --------------------------------------------------------------------------------------------------
def _break_with_undefined_function(monkeypatch):
    """The lookup now calls a function that does not exist: PostgreSQL itself raises UndefinedFunction (a real server error)."""
    monkeypatch.setattr(
        v, "func", SimpleNamespace(upper=sa.func.no_such_function_for_rollback_test)
    )


def _break_with_slow_query(monkeypatch):
    """The lookup now sleeps on the server; with statement_timeout the server cancels it (a real query timeout)."""

    def slow(col):
        return sa.func.upper(sa.func.concat(sa.cast(sa.func.pg_sleep(2), sa.Text), col))

    monkeypatch.setattr(v, "func", SimpleNamespace(upper=slow))


@pytest.mark.parametrize(
    "breaker",
    [_break_with_undefined_function, _break_with_slow_query],
    ids=["undefined_function", "statement_timeout"],
)
async def test_real_registry_failure_keeps_the_analysis_and_reports_unknown(
    ctx, monkeypatch, breaker
):
    baseline = await analyze(
        ctx, SCAM
    )  # no sender; its alert is written inside the rolled-back transaction
    alerts_before = await alert_count(ctx)
    await ctx.conn.exec_driver_sql("SET LOCAL statement_timeout = '100ms'")

    breaker(monkeypatch)
    r = await analyze(ctx, SCAM, "VM-RBTST1-S")
    monkeypatch.undo()
    await ctx.conn.exec_driver_sql("SET LOCAL statement_timeout = 0")

    # usable response, analysis preserved
    assert (
        r.risk_score == baseline.risk_score == 90
        and baseline.verdict.risk_score == 70
        and r.detected_patterns == baseline.detected_patterns
    )
    # sender is UNKNOWN / unavailable, never UNREGISTERED, and there is no false registry warning
    assert (r.sender_validation.verdict, r.sender_validation.lookup_status) == (
        "UNKNOWN",
        "unavailable",
    )
    assert not any("TRAI registry" in f for f in r.red_flags)
    # shared verdict explains it and is not changed by the outage
    assert r.verdict.risk_score == baseline.verdict.risk_score
    assert any("could not be verified" in lim for lim in r.verdict.limitations)
    assert "sender_not_registered" not in {e.code for e in r.verdict.evidence}
    # the session and the transaction recovered: the alert was saved after the failure, and a healthy lookup works again
    assert await alert_count(ctx) == alerts_before + 1
    assert (await ctx.session.execute(text("select 1"))).scalar_one() == 1
    again = await v.validate_sender_safe("VM-RBTST1-S", ctx.session)
    assert (again["verdict"], again["lookup_status"]) == ("REGISTERED", "ok")
    # fixture rows (inserted outside the session's savepoint) survived the savepoint rollback
    assert (
        await ctx.conn.execute(
            text("select count(*) from sms_sender_registry where header = any(:h)"),
            {"h": [h for h, _ in FIXTURE_ROWS]},
        )
    ).scalar_one() == 3


async def test_unregistered_sender_warning_is_still_produced_when_the_registry_is_healthy(
    ctx,
):
    r = await analyze(ctx, SCAM, "VM-NOSUCH-S")
    assert (
        r.sender_validation.verdict == "UNREGISTERED"
        and r.risk_score == 100
        and r.verdict.risk_score == 90
    )  # legacy 90+20 capped at 100; verdict 70+20
    assert any("TRAI registry" in f for f in r.red_flags)
    assert "sender_not_registered" in {e.code for e in r.verdict.evidence}


# ---- cleanup -----------------------------------------------------------------------------------------------------------------------
async def test_rollback_restores_every_table_and_the_revision(ctx):
    # write something extra, then let the fixture's teardown prove it is gone: it asserts all per-table counts equal ``before``
    await analyze(ctx, SCAM, "VM-RBTST1-S")
    mid = await _counts(ctx.conn)
    assert mid["sms_sender_registry"] == ctx.before["sms_sender_registry"] + 3
    assert (
        mid["users"] == ctx.before["users"] + 1
        and mid["alerts"] >= ctx.before["alerts"] + 1
    )
    assert mid["alembic_version"] == ctx.before["alembic_version"]


# ---- Stage 1.6D-2: what is actually persisted and read back ---------------------------------------------------------------------
async def test_persisted_alert_row_holds_only_redacted_values(ctx):
    otp, acct, phone, secret = "482913", "123456789012", "9876543210", "SEKRET99"
    msg = f"URGENT: your account {acct} is blocked. Share your OTP {otp} and click https://evil.example/kyc?t={secret} or call {phone}"
    await analyze(ctx, msg, f"+91{phone}")
    row = (
        await ctx.conn.execute(
            sa.select(Alert.title, Alert.message, Alert.extra_data).where(
                Alert.user_id == ctx.user.id
            )
        )
    ).one()
    stored = f"{row.title} {row.message} {row.extra_data}"
    for raw in (otp, acct, phone, secret):
        assert raw not in stored
    assert (
        row.extra_data["sender"] == "[PHONE ...10]"
        and "[link: evil.example]" in row.extra_data["message_preview"]
    )
    assert len(row.extra_data["message_preview"]) <= 100


# ---- Stage 1.6D-3: the other alert writers, read back from PostgreSQL ------------------------------------------------------------
async def test_scam_call_community_and_wifi_alert_rows_are_redacted_in_postgres(ctx):
    from app.routers import community_scam as cs
    from app.routers import scam_calls as sc
    from app.routers import wifi as wf
    from app.schemas.scam_call import ScamCallReportRequest
    from app.schemas.wifi_scan import WifiScanRequest

    phone, otp, acct = "9876543210", "482913", "123456789012"
    await sc.report_scam_call(
        ScamCallReportRequest(
            caller_number=f"+91{phone}",
            detection_reason=f"digital arrest, OTP {otp}, a/c {acct}",
        ),
        ctx.user,
        ctx.session,
    )
    for _ in range(5):  # the 5th report of the same number raises the community alert
        await cs.report_scam(
            cs.ScamReportRequest(
                scam_type=list(cs.ScamType)[0],
                title="Fake KYC call",
                description="asked for money",
                phone_number=f"+91{phone}",
            ),
            ctx.user,
            ctx.session,
        )
    await wf.scan_wifi(
        WifiScanRequest(
            ssid=f"Flat {phone}",
            bssid="aa:bb:cc:dd:ee:ff",
            signal_strength=-40,
            encryption_type="OPEN",
        ),
        ctx.user,
        ctx.session,
    )
    rows = (
        await ctx.conn.execute(
            sa.select(
                Alert.alert_type, Alert.title, Alert.message, Alert.extra_data
            ).where(Alert.user_id == ctx.user.id)
        )
    ).all()
    kinds = {r.alert_type.value for r in rows}
    assert {"scam_call", "community_scam", "wifi_unsafe"} <= kinds, kinds
    for r in rows:
        stored = f"{r.title} {r.message} {r.extra_data}"
        for raw in (phone, otp, acct):
            assert raw not in stored, (r.alert_type, raw)
    # the user's own records keep what is needed to block or look up the number
    assert (
        await ctx.conn.execute(
            text(
                "select count(*) from scam_calls where caller_number like '%9876543210'"
            )
        )
    ).scalar_one() == 1
    assert (
        await ctx.conn.execute(
            text(
                "select count(*) from community_scam_reports where phone_number like '%9876543210'"
            )
        )
    ).scalar_one() == 5
