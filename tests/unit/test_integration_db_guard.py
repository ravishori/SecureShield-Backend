"""The integration harness must refuse anything that isn't a local test DB."""

import pytest

from tests.integration.conftest import (
    UnsafeTestDatabaseError,
    assert_safe_test_database,
)


def _url(host: str, db: str) -> str:
    netloc = f"[{host}]" if ":" in host else host  # IPv6 literals need brackets
    return f"postgresql+asyncpg://user:pw@{netloc}:5432/{db}"


class TestAssertSafeTestDatabase:
    @pytest.mark.unit
    @pytest.mark.security
    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
    def test_loopback_test_db_is_accepted(self, host):
        assert_safe_test_database(_url(host, "secureshield_cw_test"))

    @pytest.mark.unit
    @pytest.mark.security
    def test_azure_host_is_rejected(self):
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database(
                _url(
                    "secureshield-pg-prod.postgres.database.azure.com",
                    "SecureShieldDB_test",
                )
            )

    @pytest.mark.unit
    @pytest.mark.security
    def test_non_test_database_name_is_rejected(self):
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database(_url("localhost", "SecureShieldDB"))

    @pytest.mark.unit
    @pytest.mark.security
    def test_name_must_end_with_test_not_merely_contain_it(self):
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database(_url("localhost", "test_production"))

    @pytest.mark.unit
    @pytest.mark.security
    def test_remote_host_rejected_even_with_test_name(self):
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database(_url("10.1.2.3", "app_test"))

    @pytest.mark.unit
    def test_extra_host_allow_list_is_honoured(self, monkeypatch):
        monkeypatch.setenv("TEST_DATABASE_ALLOWED_HOSTS", "postgres, ci-db")
        assert_safe_test_database(_url("ci-db", "app_test"))

    @pytest.mark.unit
    @pytest.mark.security
    def test_extra_hosts_still_cannot_be_cloud_managed(self, monkeypatch):
        monkeypatch.setenv(
            "TEST_DATABASE_ALLOWED_HOSTS", "x.postgres.database.azure.com"
        )
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database(_url("x.postgres.database.azure.com", "a_test"))

    @pytest.mark.unit
    def test_garbage_url_is_rejected(self):
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database("not a url")
