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


# ------------------------------------------------ failure injection (isolated test data only)
def _setup_old_file(tmp_path, ring, monkeypatch, data=b"precious evidence" * 1000):
    write(tmp_path / "f", data, 0)
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    return (tmp_path / "f").read_bytes(), data


def _no_leftovers(tmp_path):
    return not [p for p in tmp_path.iterdir() if p.name.startswith(".rotate-")]


def test_crash_while_writing_the_new_copy_preserves_the_original(
    tmp_path, ring, monkeypatch
):
    before, data = _setup_old_file(tmp_path, ring, monkeypatch)
    real_write = fc.EncryptingWriter.write
    calls = {"n": 0}

    def dying_write(self, chunk):
        calls["n"] += 1
        real_write(self, chunk)
        raise OSError("disk full / process killed")

    monkeypatch.setattr(fc.EncryptingWriter, "write", dying_write)
    assert rot.main([str(tmp_path)]) == 2
    assert calls["n"] == 1
    assert (tmp_path / "f").read_bytes() == before and read(tmp_path / "f") == data
    assert _no_leftovers(tmp_path)


def test_crash_before_the_final_record_is_written_preserves_the_original(
    tmp_path, ring, monkeypatch
):
    before, data = _setup_old_file(tmp_path, ring, monkeypatch)

    def dying_close(self):
        raise OSError("killed before the final record")

    monkeypatch.setattr(fc.EncryptingWriter, "close", dying_close)
    assert rot.main([str(tmp_path)]) == 2
    assert (tmp_path / "f").read_bytes() == before and _no_leftovers(tmp_path)


def test_verification_failure_never_replaces_the_original(
    tmp_path, ring, monkeypatch, capsys
):
    before, data = _setup_old_file(tmp_path, ring, monkeypatch)
    real = rot._plain_digest_encrypted

    def lying(path):
        digest = real(path)
        # the original is read first; the re-encrypted temp copy then "hashes" differently
        return digest if os.path.basename(path) == "f" else "0" * 64

    monkeypatch.setattr(rot, "_plain_digest_encrypted", lying)
    assert rot.main([str(tmp_path)]) == 2
    assert "verification" in capsys.readouterr().err
    assert (tmp_path / "f").read_bytes() == before and _no_leftovers(tmp_path)


def test_replacement_failure_preserves_the_original_and_cleans_up(
    tmp_path, ring, monkeypatch
):
    before, data = _setup_old_file(tmp_path, ring, monkeypatch)

    def boom(src, dst):
        raise PermissionError("file locked")

    monkeypatch.setattr(rot.os, "replace", boom)
    assert rot.main([str(tmp_path)]) == 2
    assert (tmp_path / "f").read_bytes() == before and _no_leftovers(tmp_path)


def test_wrong_old_key_is_reported_and_leaves_the_file_alone(
    tmp_path, ring, monkeypatch, capsys
):
    write(tmp_path / "f", b"secret", 1)
    before = (tmp_path / "f").read_bytes()
    # operator configures a DIFFERENT key under id 1 by mistake
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEYS", f"1:{k()},2:{ring['k2']}")
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    assert rot.main([str(tmp_path)]) == 2
    assert "authentication failed" in capsys.readouterr().err
    assert (tmp_path / "f").read_bytes() == before and _no_leftovers(tmp_path)


def test_interrupted_rotation_can_simply_be_rerun(tmp_path, ring, monkeypatch):
    datas = {f"f{i}": os.urandom(5000 + i) for i in range(4)}
    for name, d in datas.items():
        write(tmp_path / name, d, 0)
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    real_replace = os.replace
    seen = {"n": 0}

    def flaky(src, dst):
        seen["n"] += 1
        if seen["n"] == 3:
            raise OSError("power cut")
        real_replace(src, dst)

    monkeypatch.setattr(rot.os, "replace", flaky)
    assert (
        rot.main([str(tmp_path)]) == 2
    )  # 2 rotated, 1 failed, 1 untouched-by-this-run? (all attempted)
    ids = sorted(fc.file_key_id(str(tmp_path / n)) for n in datas)
    assert (
        ids.count(2) == 3 and ids.count(0) == 1
    )  # a clean mixed state: every file still readable
    for n, d in datas.items():
        assert read(tmp_path / n) == d
    monkeypatch.setattr(rot.os, "replace", real_replace)
    assert rot.main([str(tmp_path)]) == 0  # re-run finishes the job
    assert all(fc.file_key_id(str(tmp_path / n)) == 2 for n in datas) and _no_leftovers(
        tmp_path
    )
    for n, d in datas.items():
        assert read(tmp_path / n) == d


def test_stale_temp_files_from_a_killed_run_are_ignored_not_rotated(
    tmp_path, ring, monkeypatch
):
    (tmp_path / ".rotate-abc123").write_bytes(b"half written garbage")
    write(tmp_path / "real", b"data", 0)
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    assert rot.main([str(tmp_path)]) == 0
    assert (tmp_path / ".rotate-abc123").read_bytes() == b"half written garbage"
    assert fc.file_key_id(str(tmp_path / "real")) == 2


def test_no_plaintext_is_left_on_disk_after_rotation_and_empty_files_survive(
    tmp_path, ring, monkeypatch
):
    write(tmp_path / "e", b"", 0)
    write(tmp_path / "s", b"TOP-SECRET-MARKER" * 10, 0)
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "2")
    assert rot.main([str(tmp_path)]) == 0
    assert read(tmp_path / "e") == b""
    assert b"TOP-SECRET-MARKER" not in (tmp_path / "s").read_bytes()
