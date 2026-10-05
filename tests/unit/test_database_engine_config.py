"""The production engine must not embed bound SQL parameters in error text."""

import pytest


@pytest.mark.unit
@pytest.mark.security
def test_app_engine_hides_sql_parameters():
    from app.database import engine

    assert engine.sync_engine.hide_parameters is True
