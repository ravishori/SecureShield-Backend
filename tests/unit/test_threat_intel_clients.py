"""Google Safe Browsing and URLhaus client behaviour against simulated provider responses.

httpx.MockTransport stands in for the remote API (status codes, bodies, timeouts) so the
client logic - request shape, credentials handling, retries, error classification and what
reaches callers - is tested for real. Live behaviour needs real provider keys (not in CI)."""

import asyncio

import httpx
import pytest

from app.services import gsb_service as gsb
from app.services import urlhaus_service as uh

KEY = "AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKE12345"
UKEY = "urlhaus-FAKE-auth-key-123456"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    gsb._cache.clear()
    uh._cache.clear()

    async def _nosleep(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _nosleep)
    monkeypatch.setattr(gsb, "GSB_API_KEY", KEY)
    monkeypatch.setattr(uh.settings, "URLHAUS_AUTH_KEY", UKEY, raising=False)


_REAL_CLIENT = httpx.AsyncClient  # captured once: _mock() may be called several times per test


def _mock(monkeypatch, handler):
    def factory(*a, **k):
        k["transport"] = httpx.MockTransport(handler)
        return _REAL_CLIENT(*a, **k)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


# ───────────────────────────────── Google Safe Browsing ─────────────────────────────────
@pytest.mark.unit
@pytest.mark.security
async def test_gsb_sends_key_in_header_never_in_url(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["key_header"] = request.headers.get("x-goog-api-key")
        return httpx.Response(200, json={})

    _mock(monkeypatch, handler)
    r = await gsb.check_url_gsb("https://example.org/a")
    assert r["status"] == "safe"
    assert KEY not in seen["url"] and "key=" not in seen["url"]
    assert seen["key_header"] == KEY


@pytest.mark.unit
async def test_gsb_malicious_match_is_parsed(monkeypatch):
    body = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM",
                         "threatEntryType": "URL", "threat": {"url": "http://bad.example/"}}]}
    _mock(monkeypatch, lambda req: httpx.Response(200, json=body))
    r = await gsb.check_url_gsb("http://bad.example/")
    assert r["status"] == "malicious" and r["safe"] is False
    assert r["threats"][0]["threat_type"] == "SOCIAL_ENGINEERING"
    assert r["threats"][0]["threat_label"].startswith("Phishing")


@pytest.mark.unit
async def test_gsb_without_key_is_inconclusive_and_makes_no_request(monkeypatch):
    monkeypatch.setattr(gsb, "GSB_API_KEY", "")
    calls = []
    _mock(monkeypatch, lambda req: calls.append(req) or httpx.Response(200, json={}))
    r = await gsb.check_url_gsb("https://example.org/")
    assert r["status"] == "no_api_key" and calls == []


@pytest.mark.unit
@pytest.mark.parametrize("code,expected_status,expected_reason", [
    (400, "http_error", "bad_request"), (401, "http_error", "auth_failed"), (403, "http_error", "auth_failed"),
])
async def test_gsb_client_errors_are_classified(monkeypatch, code, expected_status, expected_reason):
    _mock(monkeypatch, lambda req: httpx.Response(code, text="nope"))
    r = await gsb.check_url_gsb("https://example.org/")
    assert (r["status"], r["reason"], r["http_status"]) == (expected_status, expected_reason, code)


@pytest.mark.unit
async def test_gsb_rate_limit_retries_then_reports(monkeypatch):
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(429, text="slow down")

    _mock(monkeypatch, handler)
    r = await gsb.check_url_gsb("https://example.org/")
    assert r["status"] == "rate_limited" and n["c"] == gsb.GSB_MAX_RETRIES + 1


@pytest.mark.unit
async def test_gsb_transient_5xx_recovers_on_retry(monkeypatch):
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(503) if n["c"] == 1 else httpx.Response(200, json={})

    _mock(monkeypatch, handler)
    assert (await gsb.check_url_gsb("https://example.org/"))["status"] == "safe" and n["c"] == 2


@pytest.mark.unit
async def test_gsb_timeout_and_connection_errors_are_network_errors(monkeypatch):
    def timeout(req):
        raise httpx.ReadTimeout("slow", request=req)

    _mock(monkeypatch, timeout)
    assert (await gsb.check_url_gsb("https://a.example/"))["reason"] == "timeout"

    def refuse(req):
        raise httpx.ConnectError(f"cannot reach {req.url}", request=req)

    _mock(monkeypatch, refuse)
    r = await gsb.check_url_gsb("https://b.example/")
    assert r["status"] == "network_error" and r["reason"] == "ConnectError"


@pytest.mark.unit
@pytest.mark.security
async def test_gsb_unexpected_errors_never_echo_text_that_could_hold_the_key(monkeypatch):
    def boom(req):
        raise RuntimeError(f"failed calling {req.url} with key {KEY}")

    _mock(monkeypatch, boom)
    r = await gsb.check_url_gsb("https://example.org/")
    assert r["status"] == "unknown_error"
    assert KEY not in repr(r) and r["reason"] == "RuntimeError"


@pytest.mark.unit
async def test_gsb_results_are_cached(monkeypatch):
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(200, json={})

    _mock(monkeypatch, handler)
    await gsb.check_url_gsb("https://example.org/c")
    again = await gsb.check_url_gsb("https://example.org/c")
    assert n["c"] == 1 and again["cached"] is True


# ─────────────────────────────────────── URLhaus ───────────────────────────────────────
@pytest.mark.unit
async def test_urlhaus_without_auth_key_is_honest_and_makes_no_request(monkeypatch):
    monkeypatch.setattr(uh.settings, "URLHAUS_AUTH_KEY", "", raising=False)
    calls = []
    _mock(monkeypatch, lambda req: calls.append(req) or httpx.Response(200, json={}))
    r = await uh.check_url_urlhaus("http://x.example/")
    assert r["status"] == "no_api_key" and r["safe"] is False and calls == []


@pytest.mark.unit
@pytest.mark.security
async def test_urlhaus_sends_auth_key_header_and_form_body(monkeypatch):
    seen = {}

    def handler(req: httpx.Request):
        seen["h"] = req.headers.get("auth-key")
        seen["body"] = req.content.decode()
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"query_status": "no_results"})

    _mock(monkeypatch, handler)
    r = await uh.check_url_urlhaus("http://x.example/p?q=1")
    assert r["status"] == "safe" and r["reason"] == "not_in_database"
    assert seen["h"] == UKEY and UKEY not in seen["url"]
    assert seen["body"].startswith("url=")


@pytest.mark.unit
async def test_urlhaus_known_bad_url_is_malicious(monkeypatch):
    body = {"query_status": "ok", "threat": "malware_download", "url": "http://bad.example/m.exe",
            "tags": ["exe"], "date_added": "2026-01-01"}
    _mock(monkeypatch, lambda req: httpx.Response(200, json=body))
    r = await uh.check_url_urlhaus("http://bad.example/m.exe")
    assert r["status"] == "malicious"
    assert r["threats"][0]["threat_label"] == "Malware Download" and r["threats"][0]["tags"] == ["exe"]


@pytest.mark.unit
@pytest.mark.parametrize("code,reason", [(401, "auth_failed"), (403, "auth_failed"), (404, "unexpected_status")])
async def test_urlhaus_http_errors(monkeypatch, code, reason):
    _mock(monkeypatch, lambda req: httpx.Response(code))
    r = await uh.check_url_urlhaus("http://x.example/")
    assert r["status"] == "http_error" and r["reason"] == reason


@pytest.mark.unit
async def test_urlhaus_5xx_retries_then_errors_and_network_errors_are_typed(monkeypatch):
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(502)

    _mock(monkeypatch, handler)
    r = await uh.check_url_urlhaus("http://x.example/")
    assert r["status"] == "http_error" and n["c"] == uh.URLHAUS_MAX_RETRIES + 1

    def refuse(req):
        raise httpx.ConnectError(f"unreachable {req.url}", request=req)

    _mock(monkeypatch, refuse)
    r = await uh.check_url_urlhaus("http://y.example/")
    assert r["status"] == "network_error" and r["reason"] == "ConnectError"
