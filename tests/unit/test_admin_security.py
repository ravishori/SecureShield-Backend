"""Credential primitives for admin accounts: passwords, TOTP (RFC 6238 vectors), secret encryption, recovery codes."""

import pytest

from app.services import admin_security as S

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of the ASCII string 12345678901234567890 (RFC 6238 appendix B)


@pytest.mark.unit
@pytest.mark.security
class TestPasswords:
    def test_roundtrip_and_salting(self):
        a, b = (
            S.hash_password("correct horse 9 battery"),
            S.hash_password("correct horse 9 battery"),
        )
        assert a != b and a.startswith("scrypt$")
        assert S.verify_password("correct horse 9 battery", a)
        assert not S.verify_password("correct horse 9 batterY", a)

    @pytest.mark.parametrize(
        "bad",
        ["", "plaintext", "scrypt$1$2$3", "md5$a$b$c$d$e", "scrypt$x$8$1$AAAA$AAAA"],
    )
    def test_malformed_hashes_never_verify_and_never_raise(self, bad):
        assert S.verify_password("anything", bad) is False

    def test_dummy_hash_is_a_valid_hash_that_matches_nothing_guessable(self):
        assert S.DUMMY_HASH.startswith("scrypt$")
        assert not S.verify_password("password", S.DUMMY_HASH)

    @pytest.mark.parametrize(
        "pw, email, fragment",
        [
            ("short1!", None, "at least"),
            ("aaaaaaaaaaaaaaaa", None, "repetitive"),
            ("secureshield", None, "too common"),
            ("ops-team-9-long-pass", "ops-team-9@example.org", "e-mail"),
            ("onlylettersnodigits", None, "mix letters"),
            ("x" * 300, None, "at most"),
        ],
    )
    def test_weak_passwords_are_rejected(self, pw, email, fragment):
        assert any(fragment in p for p in S.password_problems(pw, email)), (
            S.password_problems(pw, email)
        )

    def test_a_reasonable_password_passes(self):
        assert S.password_problems("Tr0ub4dor&3-horse-staple", "ops@example.org") == []


@pytest.mark.unit
@pytest.mark.security
class TestTotp:
    # RFC 6238 appendix B (SHA-1); the 8-digit values truncated to the last 6 digits we use.
    @pytest.mark.parametrize(
        "t, expected",
        [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ],
    )
    def test_rfc_6238_vectors(self, t, expected):
        assert S.totp_code(RFC_SECRET, S.current_step(t)) == expected

    def test_window_accepts_one_step_of_drift_either_way(self):
        now = 1234567890.0
        step = S.current_step(now)
        for s in (step - 1, step, step + 1):
            assert S.verify_totp(RFC_SECRET, S.totp_code(RFC_SECRET, s), 0, now) == s
        for s in (step - 2, step + 2):
            assert S.verify_totp(RFC_SECRET, S.totp_code(RFC_SECRET, s), 0, now) is None

    def test_a_code_cannot_be_used_twice_nor_an_older_one_after_a_newer(self):
        now = 1234567890.0
        step = S.current_step(now)
        code = S.totp_code(RFC_SECRET, step)
        assert S.verify_totp(RFC_SECRET, code, step - 1, now) == step
        assert S.verify_totp(RFC_SECRET, code, step, now) is None  # replay
        assert (
            S.verify_totp(RFC_SECRET, S.totp_code(RFC_SECRET, step - 1), step, now)
            is None
        )

    @pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 5", None])
    def test_malformed_codes_are_rejected(self, bad):
        assert S.verify_totp(RFC_SECRET, bad, 0, 1234567890.0) is None

    def test_spaces_inside_a_pasted_code_are_tolerated(self):
        now = 1234567890.0
        code = S.totp_code(RFC_SECRET, S.current_step(now))
        assert S.verify_totp(RFC_SECRET, f"{code[:3]} {code[3:]}", 0, now) is not None

    def test_new_secrets_are_random_base32_with_enough_entropy(self):
        a, b = S.new_totp_secret(), S.new_totp_secret()
        assert (
            a != b
            and len(a) >= 32
            and set(a) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        )

    def test_uri_has_the_standard_shape_and_escapes_the_label(self):
        uri = S.totp_uri("ABCDEF", "ops+1@example.org", "SecureShield AI")
        assert uri.startswith(
            "otpauth://totp/SecureShield%20AI%3Aops%2B1%40example.org?secret=ABCDEF"
        )
        assert "digits=6" in uri and "period=30" in uri


@pytest.mark.unit
@pytest.mark.security
class TestSecretsAndRecovery:
    def test_secret_encryption_roundtrip_hides_the_value_and_detects_tampering(self):
        token = S.encrypt_secret("JBSWY3DPEHPK3PXP")
        assert "JBSWY3DPEHPK3PXP" not in token
        assert S.decrypt_secret(token) == "JBSWY3DPEHPK3PXP"
        assert S.decrypt_secret(token[:-4] + "AAAA") is None
        assert S.decrypt_secret("not-a-token") is None

    def test_recovery_codes_are_unique_hashed_and_single_use(self):
        shown, stored = S.new_recovery_codes()
        assert len(shown) == len(stored) == S.RECOVERY_CODE_COUNT == len(set(shown))
        assert all(len(c) == 11 and c[5] == "-" for c in shown)
        assert not any(
            c.replace("-", "") in h for c in shown for h in stored
        )  # only hashes are kept
        left = S.consume_recovery_code(stored, shown[0])
        assert left is not None and len(left) == len(stored) - 1
        assert S.consume_recovery_code(left, shown[0]) is None  # one use only
        assert (
            S.consume_recovery_code(left, shown[1].upper().replace("-", "")) is not None
        )  # case/dash tolerant

    def test_wrong_recovery_code_is_rejected(self):
        _, stored = S.new_recovery_codes()
        assert S.consume_recovery_code(stored, "aaaaa-bbbbb") is None
        assert S.consume_recovery_code([], "aaaaa-bbbbb") is None
