"""Encryption key lifecycle: keyring, key ids, and scripts/rotate_file_keys.py."""

import base64
import os
import sys
from pathlib import Path

import pytest

import app.services.file_crypto as fc
from app.config import settings

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import rotate_file_keys as rot  # noqa: E402

pytestmark = pytest.mark.unit


def k():
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


@pytest.fixture
def ring(monkeypatch):
    keys = {"old": k(), "k1": k(), "k2": k()}
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", keys["old"])
    monkeypatch.setattr(
        settings, "FILE_ENCRYPTION_KEYS", f"1:{keys['k1']},2:{keys['k2']}"
    )
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "0")
    return keys


def write(path, data, kid):
    active = fc.keyring()[kid]
    with open(path, "wb") as fh:
        w = fc.EncryptingWriter(fh, active, kid)
        w.write(data)
        w.close()


def read(path):
    return b"".join(fc.decrypt_iter(str(path)))


def test_formats_and_key_ids(tmp_path, ring):
    write(tmp_path / "a", b"alpha", 0)
    write(tmp_path / "b", b"beta", 2)
    assert fc.file_key_id(str(tmp_path / "a")) == 0 and (
        tmp_path / "a"
    ).read_bytes().startswith(fc.MAGIC)
    assert fc.file_key_id(str(tmp_path / "b")) == 2 and (
        tmp_path / "b"
    ).read_bytes().startswith(fc.MAGIC2)
    (tmp_path / "p").write_bytes(b"plain")
    assert fc.file_key_id(str(tmp_path / "p")) is None
    assert (
        read(tmp_path / "a") == b"alpha" and read(tmp_path / "b") == b"beta"
    )  # old and new ids both readable


def test_active_key_selection_rules(monkeypatch, ring):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    assert fc.active_key()[0] == 2
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "")
    with pytest.raises(
        fc.FileCryptoError
    ):  # several keys, none selected: refuse to guess
        fc.active_key()
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "9")
    with pytest.raises(fc.FileCryptoError):
        fc.active_key()
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEYS", "x:abc")
    with pytest.raises(fc.FileCryptoError):
        fc.keyring()
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEYS", f"0:{k()}")
    with pytest.raises(fc.FileCryptoError):
        fc.keyring()


def test_a_file_under_an_unconfigured_key_is_unreadable_not_misread(
    tmp_path, ring, monkeypatch
):
    write(tmp_path / "b", b"beta", 2)
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEYS", f"1:{ring['k1']}")
    with pytest.raises(fc.FileCryptoError, match="key id 2"):
        read(tmp_path / "b")


def test_rotation_moves_every_file_to_the_active_key_and_is_idempotent(
    tmp_path, ring, monkeypatch, capsys
):
    big = os.urandom(fc.RECORD * 2 + 7)
    write(tmp_path / "old", b"legacy secret", 0)
    write(tmp_path / "mid", big, 1)
    write(tmp_path / "cur", b"already", 2)
    (tmp_path / "plain").write_bytes(b"not encrypted")
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")

    assert rot.main([str(tmp_path), "--dry-run"]) == 0
    assert (
        "would rotate=2" in capsys.readouterr().out
        and fc.file_key_id(str(tmp_path / "old")) == 0
    )

    assert rot.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert (
        "rotated=2" in out
        and "already_current=1" in out
        and "plaintext_skipped=1" in out
    )
    for name, data in (("old", b"legacy secret"), ("mid", big), ("cur", b"already")):
        assert (
            fc.file_key_id(str(tmp_path / name)) == 2 and read(tmp_path / name) == data
        )
    assert (tmp_path / "plain").read_bytes() == b"not encrypted"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".rotate-")]

    assert rot.main([str(tmp_path)]) == 0  # second run: nothing to do
    assert "rotated=0" in capsys.readouterr().out

    assert rot.main([str(tmp_path), "--encrypt-plain"]) == 0
    assert (
        fc.file_key_id(str(tmp_path / "plain")) == 2
        and read(tmp_path / "plain") == b"not encrypted"
    )

    # after rotation the retired keys are no longer needed
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", "")
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEYS", f"2:{ring['k2']}")
    assert read(tmp_path / "old") == b"legacy secret"


def test_unreadable_file_is_left_untouched_and_reported(
    tmp_path, ring, monkeypatch, capsys
):
    write(tmp_path / "good", b"good", 0)
    write(tmp_path / "bad", b"bad data", 0)
    raw = bytearray((tmp_path / "bad").read_bytes())
    raw[-3] ^= 1
    (tmp_path / "bad").write_bytes(bytes(raw))
    before = (tmp_path / "bad").read_bytes()
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    assert rot.main([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert "FAILED bad" in captured.err and "failed=1" in captured.out
    assert (tmp_path / "bad").read_bytes() == before  # not destroyed
    assert (
        fc.file_key_id(str(tmp_path / "good")) == 2
        and read(tmp_path / "good") == b"good"
    )
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".rotate-")]


def test_without_a_key_the_script_refuses(tmp_path, monkeypatch, capsys):
    for name in (
        "FILE_ENCRYPTION_KEY",
        "FILE_ENCRYPTION_KEYS",
        "FILE_ENCRYPTION_ACTIVE_KEY_ID",
    ):
        monkeypatch.setattr(settings, name, "")
    assert rot.main([str(tmp_path)]) == 1
