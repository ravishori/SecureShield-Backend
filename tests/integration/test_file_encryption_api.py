"""Encryption at rest for evidence / recordings / FIR drafts, and the on-disk format itself."""

import base64
import os
import struct

import pytest

import app.services.file_crypto as fc
from app.config import settings

pytestmark = pytest.mark.integration
EV = "/api/v1/evidence"
REC = "/api/v1/recordings"
SECRET = b"TOP-SECRET-EVIDENCE-" * 50
KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()


@pytest.fixture(autouse=True)
def _dirs(tmp_path, monkeypatch):
    import app.routers.evidence as ev
    import app.routers.recordings as rec

    for mod, name in ((ev, "evidence"), (rec, "recordings")):
        d = tmp_path / name
        d.mkdir()
        monkeypatch.setattr(mod, "UPLOAD_DIR", str(d))
    return tmp_path


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", KEY)


def only_file(tmp, kind):
    files = list((tmp / kind).iterdir())
    assert len(files) == 1
    return files[0]


async def up(client, h, data=SECRET, name="proof.txt"):
    return await client.post(
        f"{EV}/upload",
        headers=h,
        data={"title": "t"},
        files={"file": (name, data, "text/plain")},
    )


# ------------------------------------------------------------------- format
def write_enc(path, data, key=None):
    key = key or base64.urlsafe_b64decode(KEY)
    with open(path, "wb") as fh:
        w = fc.EncryptingWriter(fh, key)
        w.write(data)
        w.close()


@pytest.mark.parametrize(
    "size", [0, 1, fc.RECORD - 1, fc.RECORD, fc.RECORD + 1, fc.RECORD * 2 + 5]
)
def test_roundtrip_at_record_boundaries(tmp_path, monkeypatch, size):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", KEY)
    data = os.urandom(size)
    p = str(tmp_path / "f")
    write_enc(p, data)
    assert b"".join(fc.decrypt_iter(p)) == data
    assert fc.is_encrypted_file(p)


def test_ciphertext_does_not_contain_plaintext_and_nonces_differ(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", KEY)
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    write_enc(a, SECRET)
    write_enc(b, SECRET)
    assert b"TOP-SECRET" not in open(a, "rb").read()
    assert open(a, "rb").read() != open(b, "rb").read()  # fresh nonce prefix per file


@pytest.mark.security
def test_tamper_truncation_reorder_and_wrong_key_are_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", KEY)
    data = os.urandom(fc.RECORD * 3 + 10)
    p = tmp_path / "f"
    write_enc(str(p), data)
    raw = p.read_bytes()

    def reads(blob):
        q = tmp_path / "x"
        q.write_bytes(blob)
        return b"".join(fc.decrypt_iter(str(q)))

    flipped = bytearray(raw)
    flipped[200] ^= 1
    with pytest.raises(fc.FileCryptoError):
        reads(bytes(flipped))
    # drop the final record (classic truncation attack)
    pos = len(fc.MAGIC) + 8
    offsets = []
    while pos < len(raw):
        offsets.append(pos)
        pos += 4 + struct.unpack(">I", raw[pos : pos + 4])[0]
    with pytest.raises(fc.FileCryptoError):
        reads(raw[: offsets[-1]])
    # swap two middle records
    recs = [
        raw[offsets[i] : (offsets[i + 1] if i + 1 < len(offsets) else len(raw))]
        for i in range(len(offsets))
    ]
    swapped = raw[: offsets[0]] + recs[1] + recs[0] + b"".join(recs[2:])
    with pytest.raises(fc.FileCryptoError):
        reads(swapped)
    monkeypatch.setattr(
        settings,
        "FILE_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(os.urandom(32)).decode(),
    )
    with pytest.raises(fc.FileCryptoError):
        reads(raw)


def test_bad_key_configuration_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", "not-base64!!")
    with pytest.raises(fc.FileCryptoError):
        fc.encryption_enabled()
    monkeypatch.setattr(
        settings, "FILE_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"short").decode()
    )
    with pytest.raises(fc.FileCryptoError):
        fc.encryption_enabled()
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", "")
    assert fc.encryption_enabled() is False


# --------------------------------------------------------------- endpoints
async def test_evidence_is_encrypted_on_disk_and_decrypted_on_download(
    client, make_user, auth_headers, _dirs, keyed
):
    h = auth_headers(await make_user("enc"))
    r = await up(client, h)
    assert r.status_code == 200 and r.json()["is_encrypted"] is True
    assert r.json()["file_size_bytes"] == len(
        SECRET
    )  # plaintext size, not ciphertext size
    on_disk = only_file(_dirs, "evidence").read_bytes()
    assert b"TOP-SECRET" not in on_disk and on_disk.startswith(fc.MAGIC)
    d = await client.get(r.json()["download_url"], headers=h)
    assert d.status_code == 200 and d.content == SECRET
    assert (
        "attachment" in d.headers["content-disposition"]
        and d.headers["x-content-type-options"] == "nosniff"
    )


async def test_without_a_key_files_are_plain_and_honestly_reported(
    client, make_user, auth_headers, _dirs, monkeypatch
):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", "")
    h = auth_headers(await make_user("plain"))
    r = await up(client, h)
    assert r.json()["is_encrypted"] is False
    assert only_file(_dirs, "evidence").read_bytes() == SECRET
    assert (await client.get(r.json()["download_url"], headers=h)).content == SECRET


async def test_files_written_before_the_key_was_set_stay_downloadable(
    client, make_user, auth_headers, monkeypatch
):
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", "")
    h = auth_headers(await make_user("legacy"))
    r = await up(client, h)
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", KEY)
    assert (await client.get(r.json()["download_url"], headers=h)).content == SECRET


@pytest.mark.security
async def test_corrupt_or_unreadable_encrypted_file_is_a_clean_500_not_a_broken_download(
    client, make_user, auth_headers, _dirs, keyed, monkeypatch
):
    h = auth_headers(await make_user("bad"))
    r = await up(client, h)
    p = only_file(_dirs, "evidence")
    raw = bytearray(p.read_bytes())
    raw[-5] ^= 1
    p.write_bytes(bytes(raw))
    d = await client.get(r.json()["download_url"], headers=h)
    assert (
        d.status_code == 500
        and b"TOP-SECRET" not in d.content
        and "tag" not in d.text.lower()
    )
    # key removed while files are encrypted: also a clean error
    monkeypatch.setattr(settings, "FILE_ENCRYPTION_KEY", "")
    assert (await client.get(r.json()["download_url"], headers=h)).status_code == 500


async def test_large_upload_streams_in_multiple_records(
    client, make_user, auth_headers, _dirs, keyed
):
    h = auth_headers(await make_user("big"))
    data = os.urandom(fc.RECORD * 2 + 123)
    r = await up(client, h, data=data, name="big.bin")
    assert r.status_code == 200
    d = await client.get(r.json()["download_url"], headers=h)
    assert d.content == data


async def test_recording_and_share_link_decrypt_transparently(
    client, make_user, auth_headers, _dirs, keyed
):
    h = auth_headers(await make_user("rec"))
    mp4 = b"\x00\x00\x00\x18ftypmp42" + b"R" * 500
    r = await client.post(
        f"{REC}/upload",
        headers=h,
        data={"title": "t", "duration_seconds": "3"},
        files={"file": ("c.mp4", mp4, "video/mp4")},
    )
    assert r.status_code == 200
    assert b"ftypmp42" not in only_file(_dirs, "recordings").read_bytes()
    rid = r.json()["id"]
    assert (await client.get(f"{REC}/{rid}/download", headers=h)).content == mp4
    url = (await client.post(f"{REC}/{rid}/share-link", headers=h)).json()["share_url"]
    shared = await client.get(url)
    assert shared.content == mp4 and shared.headers["content-type"].startswith(
        "video/mp4"
    )


async def test_empty_upload_with_a_key_leaves_no_file(
    client, make_user, auth_headers, _dirs, keyed
):
    h = auth_headers(await make_user("empty"))
    r = await up(client, h, data=b"")
    assert r.status_code == 400 and list((_dirs / "evidence").iterdir()) == []
