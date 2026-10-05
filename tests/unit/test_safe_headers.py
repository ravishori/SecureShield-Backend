"""Unit guard for the error-log header allowlist."""

import pytest
from starlette.requests import Request

from app.middleware.error_handler import _MAX_HEADER_VALUE, _SAFE_HEADERS, _safe_headers


def _request(headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/x",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


@pytest.mark.unit
@pytest.mark.security
def test_allowlist_never_contains_credential_bearing_headers():
    forbidden = {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-admin-token",
        "x-api-key",
        "referer",
    }
    assert not forbidden & set(_SAFE_HEADERS)


@pytest.mark.unit
@pytest.mark.security
def test_only_allowlisted_headers_pass_and_names_are_lowercase():
    out = _safe_headers(
        _request(
            {
                "Authorization": "Bearer SECRET",
                "Cookie": "a=b",
                "X-Admin-Token": "t",
                "User-Agent": "ua",
                "X-Request-ID": "rid-1",
                "X-Whatever": "w",
            }
        )
    )
    assert out == {"user-agent": "ua", "x-request-id": "rid-1"}


@pytest.mark.unit
def test_long_values_are_truncated():
    out = _safe_headers(_request({"User-Agent": "A" * 5000}))
    assert len(out["user-agent"]) == _MAX_HEADER_VALUE


@pytest.mark.unit
def test_no_headers_gives_empty_dict():
    assert _safe_headers(_request({})) == {}
