"""Server-side encryption at rest for uploaded evidence, recordings and generated documents.

Format (``SSENC1``): ``MAGIC(8) | nonce_prefix(8) | record*`` where each record is
``length(4, big endian) | AES-256-GCM ciphertext+tag``. Plaintext is split into <= 1 MiB records so
large recordings never sit in memory. Every record's nonce is ``nonce_prefix | counter(4)`` and its
AAD is ``counter(4) | final_flag(1)``, so records cannot be reordered, dropped from the middle, or
truncated at the end (the last record must carry the final flag).

The key is ``FILE_ENCRYPTION_KEY`` (urlsafe-base64 of 32 random bytes, e.g.
``python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"``.
Without a key files are stored as before and reported as not
encrypted - nothing is claimed that is not true. Files written before the key was set stay readable:
decryption is decided per file by its magic header.

Key lifecycle
-------------
* ``FILE_ENCRYPTION_KEY`` is the original single key (key id 0, format ``SSENC1``).
* To rotate, configure a keyring ``FILE_ENCRYPTION_KEYS="1:<b64key>,2:<b64key>"`` and select the key used for
  NEW files with ``FILE_ENCRYPTION_ACTIVE_KEY_ID=2``; keep ``FILE_ENCRYPTION_KEY`` (id 0) and every older id
  until ``scripts/rotate_file_keys.py`` has re-encrypted all files, then retire them. Files written under a
  non-zero key id use format ``SSENC2``: ``MAGIC(8) | key_id(1) | nonce_prefix(8) | records``; the id is
  authenticated implicitly (a wrong id selects a wrong key and fails the tag check).
"""

from __future__ import annotations

import base64
import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

MAGIC = b"SSENC1\x00\x00"
MAGIC2 = b"SSENC2\x00\x00"
RECORD = 1024 * 1024
_LEN = struct.Struct(">I")


class FileCryptoError(Exception):
    """The file is corrupt, truncated, tampered with, or the key is wrong."""


def _decode_key(raw: str, name: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as exc:
        raise FileCryptoError(f"{name} is not valid base64") from exc
    if len(key) != 32:
        raise FileCryptoError(f"{name} must decode to exactly 32 bytes")
    return key


def keyring() -> dict[int, bytes]:
    """All configured keys by id: id 0 = FILE_ENCRYPTION_KEY, ids 1..255 from FILE_ENCRYPTION_KEYS."""
    ring: dict[int, bytes] = {}
    single = (getattr(settings, "FILE_ENCRYPTION_KEY", "") or "").strip()
    if single:
        ring[0] = _decode_key(single, "FILE_ENCRYPTION_KEY")
    for item in (getattr(settings, "FILE_ENCRYPTION_KEYS", "") or "").split(","):
        item = item.strip()
        if not item:
            continue
        kid, _, raw = item.partition(":")
        if not kid.isdigit() or not 1 <= int(kid) <= 255 or not raw:
            raise FileCryptoError(
                "FILE_ENCRYPTION_KEYS entries must look like '<1-255>:<base64 key>'"
            )
        if int(kid) in ring:
            raise FileCryptoError(f"duplicate key id {kid}")
        ring[int(kid)] = _decode_key(raw.strip(), f"FILE_ENCRYPTION_KEYS[{kid}]")
    return ring


def active_key() -> tuple[int, bytes] | None:
    """(id, key) used for new files, or None when encryption is off."""
    ring = keyring()
    if not ring:
        return None
    wanted = (getattr(settings, "FILE_ENCRYPTION_ACTIVE_KEY_ID", "") or "").strip()
    if wanted:
        if not wanted.isdigit() or int(wanted) not in ring:
            raise FileCryptoError(
                "FILE_ENCRYPTION_ACTIVE_KEY_ID does not match a configured key"
            )
        return int(wanted), ring[int(wanted)]
    if len(ring) == 1:
        kid = next(iter(ring))
        return kid, ring[kid]
    raise FileCryptoError(
        "several keys are configured: set FILE_ENCRYPTION_ACTIVE_KEY_ID"
    )


def _key() -> bytes | None:
    active = active_key()
    return active[1] if active else None


def encryption_enabled() -> bool:
    return active_key() is not None


def file_key_id(path: str) -> int | None:
    """Key id a file was written under (0 for SSENC1), or None for plaintext/unreadable files."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(len(MAGIC) + 1)
    except OSError:
        return None
    if head[: len(MAGIC)] == MAGIC:
        return 0
    if head[: len(MAGIC2)] == MAGIC2 and len(head) == len(MAGIC2) + 1:
        return head[-1]
    return None


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


def _aad(counter: int, final: bool) -> bytes:
    return struct.pack(">IB", counter, 1 if final else 0)


class EncryptingWriter:
    """File-like writer that encrypts what is written to it. ``close()`` writes the final record."""

    def __init__(self, fh: BinaryIO, key: bytes, key_id: int = 0):
        self._fh = fh
        self._aes = AESGCM(key)
        self._prefix = os.urandom(8)
        self._counter = 0
        self._pending = bytearray()
        fh.write((MAGIC if key_id == 0 else MAGIC2 + bytes([key_id])) + self._prefix)

    def _emit(self, data: bytes, final: bool) -> None:
        ct = self._aes.encrypt(
            _nonce(self._prefix, self._counter), data, _aad(self._counter, final)
        )
        self._fh.write(_LEN.pack(len(ct)) + ct)
        self._counter += 1

    def write(self, data: bytes) -> None:
        self._pending += data
        while len(self._pending) > RECORD:
            self._emit(bytes(self._pending[:RECORD]), final=False)
            del self._pending[:RECORD]

    def close(self) -> None:
        self._emit(bytes(self._pending), final=True)
        self._pending.clear()


def is_encrypted_file(path: str) -> bool:
    return file_key_id(path) is not None


def decrypt_iter(path: str) -> Iterator[bytes]:
    """Yield the plaintext of an encrypted file record by record; raises FileCryptoError on any
    corruption (including truncation)."""
    kid = file_key_id(path)
    if kid is None:
        raise FileCryptoError("not an encrypted file")
    key = keyring().get(kid)
    if key is None:
        raise FileCryptoError(
            f"file was written under key id {kid}, which is not configured"
        )
    aes = AESGCM(key)
    with open(path, "rb") as fh:
        fh.seek(len(MAGIC) + (0 if kid == 0 else 1))
        prefix = fh.read(8)
        if len(prefix) != 8:
            raise FileCryptoError("truncated header")
        counter = 0
        header = fh.read(_LEN.size)
        while True:
            if len(header) != _LEN.size:
                raise FileCryptoError("truncated file (missing final record)")
            (length,) = _LEN.unpack(header)
            if length < 16 or length > RECORD + 16:
                raise FileCryptoError("invalid record length")
            ct = fh.read(length)
            if len(ct) != length:
                raise FileCryptoError("truncated record")
            next_header = fh.read(_LEN.size)
            final = next_header == b""
            try:
                yield aes.decrypt(_nonce(prefix, counter), ct, _aad(counter, final))
            except InvalidTag as exc:
                raise FileCryptoError(
                    "authentication failed (tampered or wrong key)"
                ) from exc
            if final:
                return
            counter += 1
            header = next_header
