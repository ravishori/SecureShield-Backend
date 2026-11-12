"""FG-035: the admin token must be compared with a constant-time primitive (``hmac.compare_digest``).

What these tests establish, and what they do NOT:
  * behaviour: correct token accepted; wrong / near-miss / empty / missing / malformed tokens rejected;
    an unconfigured token fails closed (503) even for an empty header (no "'' == ''" bypass);
  * structure: ``_check_admin`` decides through ``hmac.compare_digest`` and no admin module compares the
    token with ``==`` / ``!=`` / ``in`` (AST scan, not a timing benchmark);
  * controlled mocking: the accept/reject decision really is the primitive's result.
They do NOT measure timing. The constant-time property comes from using the primitive, not from a test.
"""

from __future__ import annotations

import ast
import inspect
import logging
from pathlib import Path

import pytest
from fastapi import HTTPException

import app.routers.admin_errors as admin_errors
import app.routers.admin_users as admin_users
from app.config import settings

pytestmark = [pytest.mark.integration, pytest.mark.security]

TOKEN = "unit-test-admin-token-xyz"  # test value only, not a real credential
BASE = "/api/v1/admin"
PATHS = ("/stats", "/users", "/errors", "/errors/stats/summary", "/audit")


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", TOKEN)


def status_of(token) -> int:
    try:
        admin_errors._check_admin(token)
        return 200
    except HTTPException as exc:
        return exc.status_code


# ------------------------------------------------------------------ behaviour (unit level)
def test_correct_token_is_accepted():
    assert status_of(TOKEN) == 200


@pytest.mark.parametrize(
    "bad",
    [
        TOKEN + "x",  # longer
        TOKEN[:-1],  # shorter (prefix)
        TOKEN[1:],  # suffix
        TOKEN.upper(),  # case change
        TOKEN[:-1] + chr(ord(TOKEN[-1]) ^ 1),  # one character different
        " " + TOKEN,
        TOKEN + " ",
        TOKEN + "\x00",
        "\x00" + TOKEN,
        "x" * 10_000,
        "é" * 50,  # latin-1 range, as a header could carry
        "�",  # non-ASCII
        "0",
        "null",
    ],
)
def test_wrong_or_malformed_tokens_are_rejected(bad):
    assert status_of(bad) == 401


@pytest.mark.parametrize("missing", [None, ""])
def test_missing_or_empty_token_is_rejected(missing):
    assert status_of(missing) == 401


@pytest.mark.parametrize("unconfigured", ["", "   ", "\t\n"])
@pytest.mark.parametrize("supplied", [None, "", " ", "anything"])
def test_unconfigured_token_fails_closed_even_for_an_empty_header(
    monkeypatch, unconfigured, supplied
):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", unconfigured)
    assert status_of(supplied) == 503  # never 200: '' must not match ''


def test_configured_token_whitespace_is_trimmed_but_supplied_token_is_not(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", f"  {TOKEN}\n")
    assert status_of(TOKEN) == 200  # existing semantics: configured value is stripped
    assert status_of(f" {TOKEN}") == 401  # supplied value is compared exactly


def test_rejection_does_not_echo_the_token():
    with pytest.raises(HTTPException) as e:
        admin_errors._check_admin("attacker-supplied-value")
    assert "attacker-supplied-value" not in str(e.value.detail)
    assert TOKEN not in str(e.value.detail)


# ------------------------------------------------------------------ behaviour (HTTP level)
@pytest.mark.parametrize("path", PATHS)
async def test_every_admin_route_accepts_only_the_exact_token(client, path):
    ok = await client.get(BASE + path, headers={"X-Admin-Token": TOKEN})
    assert ok.status_code not in (401, 403, 503), (path, ok.status_code)
    for headers in (
        {},
        {"X-Admin-Token": ""},
        {"X-Admin-Token": TOKEN + "x"},
        {"X-Admin-Token": TOKEN[:-1]},
        {"X-Admin-Token": TOKEN.upper()},
        {"X-Admin-Token": ("é" * 40).encode("latin-1")},
    ):
        r = await client.get(BASE + path, headers=headers)
        assert r.status_code == 401, (path, headers, r.status_code)
        assert TOKEN not in r.text


async def test_rejected_and_accepted_requests_never_log_the_token(
    client, caplog, capsys
):
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="secureshield")
    await client.get(BASE + "/stats", headers={"X-Admin-Token": TOKEN})
    await client.get(BASE + "/stats", headers={"X-Admin-Token": TOKEN + "wrong"})
    out = capsys.readouterr()
    blob = "\n".join(r.getMessage() for r in caplog.records) + out.out + out.err
    assert TOKEN not in blob and TOKEN + "wrong" not in blob


async def test_unconfigured_admin_is_503_over_http(client, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    # An empty token header is an attempt on an unconfigured shared token; no credentials at all is just unauthenticated.
    assert (
        await client.get(BASE + "/stats", headers={"X-Admin-Token": ""})
    ).status_code == 503
    assert (await client.get(BASE + "/stats")).status_code == 401


async def test_admin_users_guard_delegates_to_the_same_check(client, monkeypatch):
    """The legacy header is judged by admin_errors._check_admin for EVERY admin router (one comparison, one throttle)."""
    calls = []
    monkeypatch.setattr(admin_errors, "_check_admin", lambda t: calls.append(t))
    r = await client.get(BASE + "/stats", headers={"X-Admin-Token": "whatever"})
    assert r.status_code == 200 and calls == ["whatever"]


# ------------------------------------------------------------------ structure
def _admin_modules():
    return [
        Path(inspect.getsourcefile(admin_errors)),
        Path(inspect.getsourcefile(admin_users)),
    ]


def test_check_admin_decides_through_hmac_compare_digest():
    tree = ast.parse(inspect.getsource(admin_errors._check_admin).lstrip())
    calls = [
        ast.unparse(n.func)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]
    assert "hmac.compare_digest" in calls
    assert admin_errors.hmac.compare_digest is __import__("hmac").compare_digest


def test_no_admin_module_compares_the_token_with_an_ordinary_operator():
    """No ==, !=, in / not in, or str methods (startswith/endswith) involving a name that holds the token."""
    suspicious = ("token", "expected", "admin_token")
    for path in _admin_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn))
                for op in node.ops
            ):
                text = ast.unparse(node).lower()
                assert not any(s in text for s in suspicious), (
                    f"{path.name}: ordinary comparison involving the admin token: {ast.unparse(node)}"
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("startswith", "endswith")
            ):
                assert not any(s in ast.unparse(node).lower() for s in suspicious), (
                    ast.unparse(node)
                )


def test_admin_token_setting_is_read_only_inside_check_admin():
    """Other app code must not compare settings.ADMIN_TOKEN itself (only _check_admin and startup checks read it)."""
    root = Path(inspect.getsourcefile(admin_errors)).parents[1]
    readers = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*.py")
        if "ADMIN_TOKEN" in p.read_text(encoding="utf-8")
    }
    assert readers <= {
        "config.py",
        "startup_checks.py",
        "routers/admin_errors.py",
    }, readers


# ------------------------------------------------------------------ controlled mocking
def test_the_decision_is_the_primitives_result(monkeypatch):
    seen = []

    def fake(a, b):
        seen.append((a, b))
        return False

    monkeypatch.setattr(admin_errors.hmac, "compare_digest", fake)
    assert status_of(TOKEN) == 401  # even the right token: the primitive said no
    assert seen == [(TOKEN.encode(), TOKEN.encode())]  # compared as bytes, exact values

    monkeypatch.setattr(admin_errors.hmac, "compare_digest", lambda a, b: True)
    assert (
        status_of("not-the-token") == 200
    )  # and yes means yes: no second ==-style gate


def test_primitive_is_not_called_for_missing_token_and_unconfigured_state(monkeypatch):
    def boom(a, b):
        raise AssertionError("compare_digest must not be reached")

    monkeypatch.setattr(admin_errors.hmac, "compare_digest", boom)
    assert status_of(None) == 401 and status_of("") == 401
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    assert status_of("x") == 503
