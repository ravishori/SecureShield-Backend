"""CORS policy: explicit allowlist, validation, per-environment behaviour and real middleware behaviour (preflight, credentials)."""

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.config import Settings
from app.cors_policy import (
    ALLOWED_HEADERS,
    ALLOWED_METHODS,
    CorsConfigError,
    resolve_cors,
)
from app.startup_checks import StartupCheckError, check_cors_configuration

pytestmark = pytest.mark.unit
OK = "https://app.example.org"
OTHER = "https://evil.example.net"


# ── resolution per environment ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("env", ["development", "dev", "local", "test", "Development"])
def test_empty_in_development_is_wildcard_without_credentials(env):
    p = resolve_cors(env, "")
    assert p.origins == ("*",) and p.allow_credentials is False


@pytest.mark.parametrize("env", ["staging", "production", "prod", "stage", "", "qa"])
def test_empty_outside_development_allows_no_browser_origin(env):
    p = resolve_cors(env, "")
    assert p.origins == () and p.allow_credentials is False


def test_unknown_environment_is_not_treated_as_development():
    assert resolve_cors("prodution", "").origins == ()  # a typo must not open CORS


@pytest.mark.parametrize("env", ["development", "staging", "production"])
def test_explicit_origins_are_used_with_credentials(env):
    p = resolve_cors(env, f"{OK}, https://other.example.org:8443")
    assert p.origins == (OK, "https://other.example.org:8443") and p.allow_credentials


def test_origins_are_normalised_and_deduplicated():
    p = resolve_cors("staging", "HTTPS://App.Example.ORG, https://app.example.org")
    assert p.origins == (OK,)


def test_wildcard_never_enables_credentials():
    assert resolve_cors("development", "*").allow_credentials is False


@pytest.mark.parametrize("env", ["staging", "production", "prod"])
def test_wildcard_is_rejected_outside_development(env):
    with pytest.raises(CorsConfigError):
        resolve_cors(env, "*")


def test_wildcard_cannot_be_mixed_with_origins_even_in_development():
    with pytest.raises(CorsConfigError):
        resolve_cors("development", f"*,{OK}")


@pytest.mark.parametrize(
    "bad",
    [
        "app.example.org",  # no scheme
        "ftp://app.example.org",
        "https://",
        "https://app.example.org/",  # trailing slash
        "https://app.example.org/path",
        "https://app.example.org?x=1",
        "https://app.example.org#frag",
        "https://user:pw@app.example.org",
        "https://*.example.org",  # wildcard subdomain
        "https://app.example.org:notaport",
        "https://app.example.org:99999",
        "null",
        "https://app example.org",
        "javascript:alert(1)",
    ],
)
@pytest.mark.parametrize("env", ["development", "staging", "production"])
def test_malformed_origins_stop_startup_instead_of_being_ignored(bad, env):
    with pytest.raises(CorsConfigError):
        resolve_cors(env, f"{OK},{bad}")


def test_production_requires_https_but_staging_and_dev_allow_http():
    with pytest.raises(CorsConfigError):
        resolve_cors("production", "http://app.example.org")
    assert resolve_cors("staging", "http://localhost:3000").origins == (
        "http://localhost:3000",
    )


def test_error_messages_do_not_echo_the_configured_value():
    secret = "https://u:supersecret@app.example.org"
    with pytest.raises(CorsConfigError) as e:
        resolve_cors("production", secret)
    assert "supersecret" not in str(e.value)


# ── startup check (all environments, not only production) ────────────────────────────────────────────────────────
def _settings(**kw) -> Settings:
    base = {
        "DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "MIGRATOR_DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "SECRET_KEY": "x" * 40,
        "SMTP_HOST": "",
        "SMTP_PORT": "25",
        "SMTP_USER": "t",
        "SMTP_PASSWORD": "t",
        "SMTP_FROM_EMAIL": "t@e.com",
        "ERROR_NOTIFY_EMAIL": "t@e.com",
        "TWILIO_ACCOUNT_SID": "AC",
        "TWILIO_AUTH_TOKEN": "t",
        "TWILIO_SMS_NUMBER": "+15555555555",
        "TWILIO_WHATSAPP_NUMBER": "+15555555555",
        "ADMIN_TOKEN": "real-admin-token-12345",
    }
    base.update(kw)
    return Settings(_env_file=None, **base)


@pytest.mark.parametrize(
    "env,origins",
    [
        ("production", "*"),
        ("staging", "*"),
        ("staging", "not-an-origin"),
        ("development", "https://x.example.org/path"),
        ("production", "http://app.example.org"),
    ],
)
def test_startup_check_refuses_unsafe_cors(env, origins):
    with pytest.raises(StartupCheckError, match="CORS"):
        check_cors_configuration(
            _settings(ENVIRONMENT=env, CORS_ALLOWED_ORIGINS=origins)
        )


@pytest.mark.parametrize(
    "env,origins",
    [
        ("production", ""),
        ("staging", ""),
        ("staging", OK),
        ("production", OK),
        ("development", "*"),
        ("test", ""),
    ],
)
def test_startup_check_accepts_safe_cors(env, origins):
    check_cors_configuration(_settings(ENVIRONMENT=env, CORS_ALLOWED_ORIGINS=origins))


# ── real middleware behaviour with the real policy constants ─────────────────────────────────────────────────────
def _client(env: str, origins: str) -> TestClient:
    policy = resolve_cors(env, origins)
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(policy.origins),
        allow_credentials=policy.allow_credentials,
        allow_methods=ALLOWED_METHODS,
        allow_headers=ALLOWED_HEADERS,
    )

    @app.get("/x")
    def x():
        return {"ok": True}

    @app.post("/x")
    def post_x():
        return {"ok": True}

    return TestClient(app)


def test_approved_origin_is_allowed_with_credentials():
    r = _client("staging", OK).get("/x", headers={"Origin": OK})
    assert r.headers["access-control-allow-origin"] == OK
    assert r.headers["access-control-allow-credentials"] == "true"


def test_unapproved_origin_gets_no_cors_headers():
    r = _client("staging", OK).get("/x", headers={"Origin": OTHER})
    # No Access-Control-Allow-Origin => the browser blocks the response (Starlette still adds a credentials header, harmless alone).
    assert "access-control-allow-origin" not in r.headers


def test_request_without_origin_header_is_unaffected_native_clients():
    r = _client("staging", OK).get("/x")
    assert r.status_code == 200 and "access-control-allow-origin" not in r.headers


def test_empty_allowlist_in_production_allows_no_browser_origin():
    r = _client("production", "").get("/x", headers={"Origin": OK})
    assert r.status_code == 200 and "access-control-allow-origin" not in r.headers


def test_preflight_for_an_approved_origin_method_and_headers_succeeds():
    r = _client("staging", OK).options(
        "/x",
        headers={
            "Origin": OK,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization, content-type",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == OK
    assert "POST" in r.headers["access-control-allow-methods"]


def test_preflight_from_an_unapproved_origin_is_refused():
    r = _client("staging", OK).options(
        "/x", headers={"Origin": OTHER, "Access-Control-Request-Method": "POST"}
    )
    assert r.status_code == 400 and "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "PROPFIND"])
def test_preflight_for_a_method_the_api_does_not_use_is_refused(method):
    r = _client("staging", OK).options(
        "/x", headers={"Origin": OK, "Access-Control-Request-Method": method}
    )
    assert r.status_code == 400


def test_preflight_for_an_arbitrary_header_is_refused():
    r = _client("staging", OK).options(
        "/x",
        headers={
            "Origin": OK,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-evil-header",
        },
    )
    assert r.status_code == 400


def test_development_wildcard_answers_star_and_never_credentials():
    r = _client("development", "").get("/x", headers={"Origin": OTHER})
    assert r.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in r.headers


def test_methods_and_headers_are_explicit_not_wildcards():
    assert "*" not in ALLOWED_METHODS and "*" not in ALLOWED_HEADERS
    assert {"Authorization", "Content-Type"} <= set(ALLOWED_HEADERS)


def test_the_real_application_uses_the_policy_constants():
    from app.main import app

    cors = next(m for m in app.user_middleware if m.cls is CORSMiddleware)
    assert cors.kwargs["allow_methods"] == ALLOWED_METHODS
    assert cors.kwargs["allow_headers"] == ALLOWED_HEADERS
    assert not (
        "*" in cors.kwargs["allow_origins"] and cors.kwargs["allow_credentials"]
    )
