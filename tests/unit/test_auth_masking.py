"""Unit tests for PII-masking helpers in `app.routers.auth`.

These functions appear in every log line and OTP response. A regression that
accidentally logs the raw email or phone is a privacy incident waiting to
happen, so these must be covered.
"""

import pytest

from app.routers.auth import _mask_email, _mask_phone, _mask


class TestMaskPhone:
    @pytest.mark.unit
    def test_full_indian_mobile_is_masked(self):
        # Original phone must not leak as a substring of the masked form.
        assert _mask_phone("+919987671916") == "+91*******916"

    @pytest.mark.unit
    def test_short_phone_is_returned_as_is(self):
        # Can't reasonably mask something < 7 chars without losing all signal.
        assert _mask_phone("12345") == "12345"
        assert _mask_phone("") == ""

    @pytest.mark.unit
    def test_masked_phone_has_same_length(self):
        original = "+447911123456"
        masked = _mask_phone(original)
        assert len(masked) == len(original), (
            "Masking must preserve length so users recognise which number it was"
        )

    @pytest.mark.unit
    def test_middle_digits_are_never_exposed(self):
        # The sensitive middle must be fully replaced with asterisks.
        original = "+919876543210"
        masked = _mask_phone(original)
        middle = masked[3:-3]
        assert all(c == "*" for c in middle), (
            "Interior digits of a phone must never appear in the masked value"
        )


class TestMaskEmail:
    @pytest.mark.unit
    def test_regular_email_is_masked(self):
        assert _mask_email("ravishori@gmail.com") == "r*******i@gmail.com"

    @pytest.mark.unit
    def test_two_char_local_only_shows_first(self):
        assert _mask_email("ab@gmail.com") == "a*@gmail.com"

    @pytest.mark.unit
    def test_single_char_local_still_masks(self):
        # Edge case: local part == 1 char. Spec: first+star+at+domain.
        assert _mask_email("a@gmail.com") == "a*@gmail.com"

    @pytest.mark.unit
    def test_domain_is_never_hidden(self):
        # Users rely on the domain to recognise accounts; must stay visible.
        assert _mask_email("longname@example.co.uk").endswith("@example.co.uk")

    @pytest.mark.unit
    def test_email_without_at_raises(self):
        # Degenerate input — caller is expected to validate before masking.
        with pytest.raises(ValueError):
            _mask_email("not-an-email")


class TestMaskDispatcher:
    @pytest.mark.unit
    def test_at_sign_routes_to_email_mask(self):
        assert _mask("ravishori@gmail.com") == "r*******i@gmail.com"

    @pytest.mark.unit
    def test_no_at_sign_routes_to_phone_mask(self):
        assert _mask("+919987671916") == "+91*******916"
