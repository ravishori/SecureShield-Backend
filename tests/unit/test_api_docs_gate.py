"""Interactive API docs must not be served in production (they enumerate every route)."""

from types import SimpleNamespace

import pytest

from app.main import api_doc_urls


@pytest.mark.unit
@pytest.mark.security
def test_docs_are_off_in_production():
    assert api_doc_urls(SimpleNamespace(is_production=lambda: True)) == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


@pytest.mark.unit
def test_docs_keep_their_defaults_outside_production():
    assert api_doc_urls(SimpleNamespace(is_production=lambda: False)) == {}


@pytest.mark.unit
@pytest.mark.security
def test_a_production_app_really_has_no_docs_routes():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI(**api_doc_urls(SimpleNamespace(is_production=lambda: True)))
    client = TestClient(app)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path
    dev = TestClient(
        FastAPI(**api_doc_urls(SimpleNamespace(is_production=lambda: False)))
    )
    assert dev.get("/openapi.json").status_code == 200
