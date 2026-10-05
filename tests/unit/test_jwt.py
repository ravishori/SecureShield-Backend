"""JWT encode/decode and lifetime tests.

Any regression here (algorithm swap, missing expiry claim, wrong secret
threading) is a direct auth bypass risk, so these are run on every PR.
"""

from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt, JWTError

from app.config import settings
from app.routers.auth import create_token


class TestCreateToken:
    @pytest.mark.unit
    @pytest.mark.security
    def test_payload_roundtrips(self):
        token = create_token(
            {"sub": "user-123", "type": "access"}, timedelta(minutes=5)
        )
        decoded = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        assert decoded["sub"] == "user-123"
        assert decoded["type"] == "access"

    @pytest.mark.unit
    @pytest.mark.security
    def test_token_has_expiry_claim(self):
        token = create_token({"sub": "u"}, timedelta(minutes=10))
        decoded = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        assert "exp" in decoded, "JWT missing exp claim — infinite-life tokens"

    @pytest.mark.unit
    @pytest.mark.security
    def test_tampered_token_fails_decode(self):
        token = create_token({"sub": "u"}, timedelta(minutes=10))
        # Flip a byte in the payload section
        parts = token.split(".")
        parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
        tampered = ".".join(parts)
        with pytest.raises(JWTError):
            jwt.decode(tampered, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    @pytest.mark.unit
    @pytest.mark.security
    def test_wrong_secret_fails_decode(self):
        token = create_token({"sub": "u"}, timedelta(minutes=10))
        with pytest.raises(JWTError):
            jwt.decode(token, "wrong-secret", algorithms=[settings.ALGORITHM])

    @pytest.mark.unit
    @pytest.mark.security
    def test_expired_token_fails_decode(self):
        # Issue a token that's already dead
        token = create_token({"sub": "u"}, timedelta(seconds=-1))
        with pytest.raises(JWTError):
            jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    @pytest.mark.unit
    @pytest.mark.security
    def test_algorithm_cannot_be_forced_to_none(self):
        """Classic JWT 'none' algorithm attack must not work.

        We can't use jose's encoder to forge the token — jose refuses to
        encode with `algorithm='none'` outright (which is good; that's one
        layer of defence). Here we hand-craft the raw bytes of a token
        claiming `alg=none` and verify the DECODER also refuses it, which
        is the defence that matters at the HTTP boundary.
        """
        import base64
        import json

        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "attacker",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }

        def b64(d):
            return (
                base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
            )

        forged = f"{b64(header)}.{b64(payload)}."  # empty signature

        with pytest.raises(JWTError):
            jwt.decode(forged, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


class TestTokenLifetimeConfiguration:
    """Asserts the HARDENED DEFAULTS in config.py.

    A deployment's .env can still override, but if the code-default drifts
    back to 24h, every fresh install gets a weak security posture by
    default. These tests pin the default to the hardened value.
    """

    @pytest.mark.unit
    @pytest.mark.security
    def test_default_access_token_lifetime_under_2h(self):
        # Build a Settings instance from DEFAULTS only (no .env file).
        # If a user's live .env overrides to 1440, that's their deployment
        # choice; this test guards against the shipped CODE regressing.
        from app.config import Settings

        base = {
            "DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
            "MIGRATOR_DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
            "SECRET_KEY": "test-only",
            "SMTP_HOST": "localhost",
            "SMTP_PORT": "1025",
            "SMTP_USER": "t",
            "SMTP_PASSWORD": "t",
            "SMTP_FROM_EMAIL": "t@e.com",
            "ERROR_NOTIFY_EMAIL": "t@e.com",
            "TWILIO_ACCOUNT_SID": "AC",
            "TWILIO_AUTH_TOKEN": "t",
            "TWILIO_SMS_NUMBER": "+15555555555",
            "TWILIO_WHATSAPP_NUMBER": "+15555555555",
        }
        s = Settings(_env_file=None, **base)
        assert s.ACCESS_TOKEN_EXPIRE_MINUTES <= 60 * 2, (
            f"Shipped default ACCESS_TOKEN_EXPIRE_MINUTES "
            f"({s.ACCESS_TOKEN_EXPIRE_MINUTES} min) exceeds the 2-hour "
            "security hardening target. See config.py."
        )

    @pytest.mark.unit
    def test_refresh_token_lifetime_is_bounded(self):
        # Reasonable upper bound — infinite refresh = no revocation.
        assert settings.REFRESH_TOKEN_EXPIRE_DAYS <= 90
