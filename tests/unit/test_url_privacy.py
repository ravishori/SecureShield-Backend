"""BH-2: what may be stored, logged, cached or sent to a provider. Pure functions; no database."""

from __future__ import annotations

import pytest

from app.services.log_scrubber import scrub_text
from app.services.url_privacy import (
    MAX_STORED_URL,
    cache_key,
    provider_url,
    redact_url_for_storage,
    redact_urls_in_text,
    sanitize_threats,
)

SECRET = "S3cr3tV4lue"


def r(url):
    return redact_url_for_storage(url)


# ----------------------------------------------------------------------------------------------------------------------
# Stored representation
# ----------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "https://example.org/2",
        "http://192.168.4.4/login/verify",
        "https://www.example.com/",
        "https://example.com/articles/how-to-spot-a-scam",
        "https://example.com:8443/a/b",
        "example.com/login",
        "HTTP://Example.COM/Path",
    ],
)
def test_plain_urls_are_stored_exactly_as_submitted(url):
    assert r(url) == url


@pytest.mark.parametrize(
    "name",
    [
        "access_token",
        "id_token",
        "token",
        "sessionid",
        "sid",
        "JSESSIONID",
        "code",
        "otp",
        "password",
        "api_key",
        "sig",
        "email",
    ],
)
def test_sensitive_query_values_are_never_stored_but_the_name_is_kept(name):
    out = r(f"https://example.com/cb?{name}={SECRET}&page=2")
    assert SECRET not in out and "page=~" in out and f"{name}=~" in out


def test_every_query_value_is_masked_not_just_known_names():
    out = r("https://shop.example/pay?u=alice@example.com&c=123456&amt=999")
    assert "alice" not in out and "123456" not in out and "999" not in out
    assert out == "https://shop.example/pay?u=~&c=~&amt=~"


def test_fragments_are_removed_including_oauth_fragment_tokens():
    out = r(f"https://example.com/cb#access_token={SECRET}&token_type=bearer")
    assert out == "https://example.com/cb" and SECRET not in out
    assert "#" not in r("https://example.com/a#b")


def test_user_info_is_removed_even_with_an_at_sign_in_the_password():
    assert (
        r(f"https://admin:{SECRET}@evil.example/panel") == "https://evil.example/panel"
    )
    assert SECRET not in r(f"https://user:p@ss{SECRET}@evil.example/")


def test_redirect_parameters_keep_only_the_target_host():
    out = r(
        f"https://example.com/login?next=https://evil.example/steal?token={SECRET}&x=1"
    )
    assert out == "https://example.com/login?next=https://evil.example&x=~"
    encoded = r(
        f"https://example.com/go?redirect_uri=https%3A%2F%2Fevil.example%2Fa%3Ft%3D{SECRET}"
    )
    assert SECRET not in encoded and "evil.example" in encoded and "/a" not in encoded
    assert (
        r("https://example.com/x?next=/dashboard") == "https://example.com/x?next=~"
    )  # not a URL: masked like any value


@pytest.mark.parametrize(
    "segment",
    [
        "9f8a7b6c5d4e3f2a1b0c9d8e",  # long hex
        "123e4567-e89b-12d3-a456-426614174000",  # uuid
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig",  # jwt
        "aB3dE5gH7jK9mN1pQ3sT5uV7",  # long mixed letters and digits
        "someone@example.com",
    ],
)
def test_token_like_path_segments_are_redacted(segment):
    out = r(f"https://example.com/reset/{segment}/confirm")
    assert segment not in out and out == "https://example.com/reset/[redacted]/confirm"


def test_malformed_and_hostile_input_never_raises_and_is_bounded():
    for bad in (
        None,
        "",
        "   ",
        "\x00\x01",
        "://",
        "http://",
        "http:///path",
        "a" * 100_000,
        "http://" + "b" * 5000 + "/" + "c" * 5000,
        "\n\r\t",
    ):
        out = r(bad)
        assert isinstance(out, str) and len(out) <= MAX_STORED_URL
    assert r("") == "[invalid-url]" and r("http:///x") == "[invalid-url]"


def test_many_parameters_are_capped():
    out = r("https://example.com/?" + "&".join(f"p{i}={SECRET}" for i in range(50)))
    assert out.count("=~") == 10 and out.endswith("...") and SECRET not in out


@pytest.mark.parametrize(
    "url",
    [
        f"https://admin:{SECRET}@e.example/reset/9f8a7b6c5d4e3f2a1b0c?token={SECRET}&next=https://x.example/y?z={SECRET}#frag",
        "https://example.com/a?b=1&c=2&d",
        "example.com/path?x=%41",
        "https://example.com/" + "p" * 2000,
    ],
)
def test_redaction_is_idempotent(url):
    once = r(url)
    assert r(once) == once


# ----------------------------------------------------------------------------------------------------------------------
# What a provider may receive
# ----------------------------------------------------------------------------------------------------------------------
def test_provider_url_removes_user_info_fragment_and_credential_parameters_only():
    out = provider_url(
        f"https://u:{SECRET}@evil.example/p?id=7&token={SECRET}&utm_source=x#frag"
    )
    assert out == "https://evil.example/p?id=7&utm_source=x"
    assert (
        provider_url("https://evil.example/p?a=1&sessionid=abc")
        == "https://evil.example/p?a=1"
    )


def test_provider_url_reduces_redirect_targets_to_their_host():
    out = provider_url(
        f"https://a.example/login?next=https://evil.example/x?k={SECRET}&page=2"
    )
    assert (
        out == "https://a.example/login?next=https://evil.example&page=2"
        and SECRET not in out
    )
    assert (
        provider_url("https://a.example/x?next=/local")
        == "https://a.example/x?next=/local"
    )


def test_provider_url_keeps_what_exact_match_feeds_need_and_returns_clean_input_unchanged():
    clean = "https://malware.example/payload.exe?id=42&v=3"
    assert provider_url(clean) is clean or provider_url(clean) == clean
    assert provider_url("example.com/x") == "example.com/x"


def test_provider_url_never_raises():
    for bad in (None, "", "\x00", "://", "a" * 50_000):
        assert isinstance(provider_url(bad), str)


def test_cache_key_does_not_contain_the_url():
    k = cache_key(f"https://example.com/?token={SECRET}")
    assert len(k) == 64 and SECRET not in k and "example" not in k


def test_threat_entries_lose_their_url_but_keep_their_meaning():
    threats = [
        {
            "threat_type": "MALWARE",
            "threat_label": "Malware",
            "url": f"https://evil.example/x?token={SECRET}#f",
        },
        "odd",
        None,
    ]
    out = sanitize_threats(threats)
    assert (
        out[0]["threat_type"] == "MALWARE"
        and out[0]["url"] == "https://evil.example/x?token=~"
    )
    assert (
        out[1:] == ["odd", None]
        and sanitize_threats(None) is None
        and sanitize_threats("x") == "x"
    )
    assert threats[0]["url"].endswith("#f")  # the input is not mutated


# ----------------------------------------------------------------------------------------------------------------------
# Free text: alert previews and logs
# ----------------------------------------------------------------------------------------------------------------------
def test_message_previews_show_only_the_host_of_a_link():
    text = f"Verify now http://evil.example/login?otp={SECRET}&u=alice#x or visit https://b.example/a."
    out = redact_urls_in_text(text)
    assert out == "Verify now [link: evil.example] or visit [link: b.example]."
    assert (
        SECRET not in out
        and redact_urls_in_text(None) is None
        and redact_urls_in_text("no link") == "no link"
    )


def test_log_text_keeps_the_path_but_not_values_fragments_or_user_info():
    line = f"GET https://api.example.com/v1/items?token={SECRET}&id=5#frag failed via https://u:{SECRET}@h.example/x"
    out = scrub_text(line)
    assert SECRET not in out and "frag" not in out and "id=5" not in out
    assert "api.example.com/v1/items" in out


def test_the_scrubber_still_redacts_credentials_outside_urls():
    out = scrub_text(
        "password=hunter2 and Bearer abcdefghijklmnop and sk-ant-" + "a" * 20
    )
    assert "hunter2" not in out and "abcdefghijklmnop" not in out
