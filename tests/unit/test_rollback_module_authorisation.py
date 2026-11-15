"""The rollback integration module only runs against an explicitly authorised, dedicated test database, and otherwise SKIPS.

No connection is ever opened here (the unit connection guard would fail the test): ``_target_url`` decides from the URL text alone.
"""

import pytest

from tests.integration import test_sender_registry_rollback as rb

pytestmark = [pytest.mark.unit, pytest.mark.security]

GOOD = "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/secureshield_test"


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.setattr(rb, "ALLOWED_DATABASES", {"secureshield_test"})
    monkeypatch.setattr(rb, "ALLOWED_PORTS", {5432})


def skipped(monkeypatch, url):
    if url is None:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("TEST_DATABASE_URL", url)
    with pytest.raises(pytest.skip.Exception) as info:
        rb._target_url()
    return str(info.value)


def test_the_dedicated_local_test_database_is_accepted(monkeypatch):
    monkeypatch.setenv("TEST_DATABASE_URL", GOOD)
    assert rb._target_url() == GOOD


def test_a_missing_url_skips(monkeypatch):
    assert "not set" in skipped(monkeypatch, None)


@pytest.mark.parametrize(
    "url,why",
    [
        (
            "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/secureshield_dev",
            "not authorised",
        ),
        (
            "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/secureshield_ci_test",
            "not authorised",
        ),
        (
            "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/postgres",
            "not authorised",
        ),
        (
            "postgresql+asyncpg://u:SENTINEL-PW@localhost:5433/secureshield_test",
            "port 5433",
        ),
        (
            "postgresql+asyncpg://u:SENTINEL-PW@db.example.com:5432/secureshield_test",
            "not loopback",
        ),
        (
            "postgresql://u:SENTINEL-PW@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB",
            "",
        ),
        ("not a url", "identity check"),
    ],
)
def test_anything_else_is_skipped_before_any_connection_and_never_leaks_credentials(
    monkeypatch, url, why
):
    reason = skipped(monkeypatch, url)
    assert why in reason
    assert "SENTINEL-PW" not in reason


def test_a_database_can_be_authorised_only_on_purpose_and_must_end_in_test(monkeypatch):
    ci = "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/secureshield_ci_test"
    monkeypatch.setattr(
        rb, "ALLOWED_DATABASES", {"secureshield_test", "secureshield_ci_test"}
    )
    monkeypatch.setenv("TEST_DATABASE_URL", ci)
    assert rb._target_url() == ci
    # the allow-list itself drops any name that is not a *_test database, so a typo cannot authorise a real one
    monkeypatch.setenv("ROLLBACK_TEST_ALLOWED_DATABASES", "secureshield_dev,production")
    import importlib

    reloaded = importlib.reload(rb)
    try:
        assert reloaded.ALLOWED_DATABASES == set()
    finally:
        monkeypatch.delenv("ROLLBACK_TEST_ALLOWED_DATABASES", raising=False)
        importlib.reload(rb)
