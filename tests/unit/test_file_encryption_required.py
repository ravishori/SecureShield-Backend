"""FILE_ENCRYPTION_REQUIRED and startup validation of the file-encryption keys (no key material is ever printed)."""

import base64
import os

import pytest
from fastapi import HTTPException

import app.services.file_crypto as fc
from app.config import settings
from app.delivery_settings import delivery_settings
from app.startup_checks import (
    StartupCheckError,
    check_file_encryption,
    run_startup_checks,
)
from app.services import upload_safety

pytestmark = pytest.mark.unit
RAW = os.urandom(32)
KEY = base64.urlsafe_b64encode(RAW).decode()


@pytest.fixture
def cfg(monkeypatch):
    def _set(key="", keys="", active="", required=False):
        monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", key, raising=False)
        monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEYS", keys, raising=False)
        monkeypatch.setattr(
            settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", active, raising=False
        )
        monkeypatch.setattr(delivery_settings, "FILE_ENCRYPTION_REQUIRED", required)

    return _set


# ── startup check ────────────────────────────────────────────────────────────────────────────────────────────────
def test_missing_key_is_fine_when_not_required(cfg):
    cfg()
    check_file_encryption(settings)


def test_missing_key_fails_startup_when_required(cfg):
    cfg(required=True)
    with pytest.raises(StartupCheckError, match="FILE_ENCRYPTION_REQUIRED"):
        check_file_encryption(settings)


def test_whitespace_only_key_counts_as_missing(cfg):
    cfg(key="   ", required=True)
    with pytest.raises(StartupCheckError):
        check_file_encryption(settings)


@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize(
    "bad",
    [
        "not*base64*at*all!",
        base64.urlsafe_b64encode(os.urandom(16)).decode(),  # 16 bytes
        base64.urlsafe_b64encode(os.urandom(31)).decode(),
        base64.urlsafe_b64encode(os.urandom(33)).decode(),
        base64.urlsafe_b64encode(os.urandom(64)).decode(),
    ],
)
def test_malformed_or_wrong_length_key_always_fails_and_is_not_echoed(
    cfg, bad, required
):
    cfg(key=bad, required=required)
    with pytest.raises(StartupCheckError) as e:
        check_file_encryption(settings)
    assert bad not in str(e.value) and "invalid" in str(e.value)


def test_valid_32_byte_key_passes_in_both_modes(cfg):
    for required in (False, True):
        cfg(key=KEY, required=required)
        check_file_encryption(settings)
        assert fc.active_key()[1] == RAW  # used directly: 32 bytes, AES-256


def test_unpadded_key_is_accepted(cfg):
    cfg(key=KEY.rstrip("="), required=True)
    check_file_encryption(settings)


@pytest.mark.parametrize(
    "keys,active",
    [
        ("1:" + KEY + ",1:" + KEY, "1"),
        ("x:" + KEY, ""),
        ("1:short", ""),
        ("1:" + KEY + ",2:" + KEY, ""),
        ("1:" + KEY, "9"),
    ],
)
def test_keyring_errors_fail_startup(cfg, keys, active):
    cfg(keys=keys, active=active)
    with pytest.raises(StartupCheckError):
        check_file_encryption(settings)


def test_valid_keyring_passes(cfg):
    cfg(
        key=KEY,
        keys="2:" + base64.urlsafe_b64encode(os.urandom(32)).decode(),
        active="2",
        required=True,
    )
    check_file_encryption(settings)


def test_check_runs_in_the_default_startup_sequence(cfg):
    cfg(required=True)
    with pytest.raises(StartupCheckError, match="FILE_ENCRYPTION_REQUIRED"):
        run_startup_checks(settings)


# ── write path: never plaintext when required ────────────────────────────────────────────────────────────────────
def test_write_key_raises_when_required_and_missing(cfg):
    cfg(required=True)
    with pytest.raises(fc.EncryptionRequiredError):
        fc.active_key_for_write()


def test_write_key_none_when_not_required_and_missing(cfg):
    cfg()
    assert fc.active_key_for_write() is None


def test_write_key_returns_key_when_configured(cfg):
    cfg(key=KEY, required=True)
    assert fc.active_key_for_write() == (0, RAW)


class _Upload:
    filename = "a.txt"
    content_type = "text/plain"

    def __init__(self, data):
        self._d, self.file = data, None

    async def read(self, n=-1):
        d, self._d = self._d, b""
        return d


@pytest.mark.asyncio
async def test_save_upload_refuses_plaintext_and_creates_no_file(cfg, tmp_path):
    cfg(required=True)
    with pytest.raises(HTTPException) as e:
        await upload_safety.save_upload(
            _Upload(b"secret"), str(tmp_path), default_name="x.txt", max_bytes=1000
        )
    assert e.value.status_code == 503 and "key" not in e.value.detail.lower()
    assert list(tmp_path.iterdir()) == []


def test_save_text_refuses_plaintext_and_creates_no_file(cfg, tmp_path):
    cfg(required=True)
    with pytest.raises(HTTPException) as e:
        upload_safety.save_text(str(tmp_path), "draft", name="fir.txt")
    assert e.value.status_code == 503
    assert list(tmp_path.iterdir()) == []


def test_save_text_encrypts_when_key_set_and_plain_when_optional(cfg, tmp_path):
    cfg(key=KEY, required=True)
    path, _ = upload_safety.save_text(str(tmp_path), "draft", name="fir.txt")
    assert fc.is_encrypted_file(path) and b"draft" not in open(path, "rb").read()
    assert b"".join(fc.decrypt_iter(path)) == b"draft"
    cfg()
    path, _ = upload_safety.save_text(str(tmp_path), "draft", name="fir2.txt")
    assert open(path, "rb").read() == b"draft" and not fc.is_encrypted_file(path)
