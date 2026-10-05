"""The test suite must never load real credentials from backend/.env."""

import pytest

from app.config import settings


class TestHermeticEnvironment:
    @pytest.mark.unit
    @pytest.mark.security
    def test_real_dotenv_is_not_loaded(self):
        assert settings.SECRET_KEY.startswith("test-secret-key-for-pytest"), (
            "settings picked up a non-test SECRET_KEY — backend/.env is leaking "
            "into the test run"
        )
        assert settings.ADMIN_TOKEN == "test-admin-token"

    @pytest.mark.unit
    @pytest.mark.security
    def test_database_url_never_targets_azure(self):
        url = settings.DATABASE_URL.lower()
        assert "azure" not in url
        assert "database.azure.com" not in url

    @pytest.mark.unit
    def test_environment_is_test(self):
        assert settings.ENVIRONMENT == "test"
        assert not settings.is_production()
