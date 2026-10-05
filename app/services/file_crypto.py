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

Key rotation is not automated: keep the old key until every file written under it is re-encrypted.
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
RECORD = 1024 * 1024
_LEN = struct.Struct(">I")


class FileCryptoError(Exception):
    """The file is corrupt, truncated, tampered with, or the key is wrong."""


def _key() -> bytes | None:
    raw = (getattr(settings, "FILE_ENCRYPTION_KEY", "") or "").strip()
    if not raw:
        return None
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as exc:
        raise FileCryptoError("FILE_ENCRYPTION_KEY is not valid base64") from exc
    if len(key) != 32:
        raise FileCryptoError("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def encryption_enabled() -> bool:
    return _key() is not None


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


def _aad(counter: int, final: bool) -> bytes:
    return struct.pack(">IB", counter, 1 if final else 0)


class EncryptingWriter:
    """File-like writer that encrypts what is written to it. ``close()`` writes the final record."""

    def __init__(self, fh: BinaryIO, key: bytes):
        self._fh = fh
        self._aes = AESGCM(key)
        self._prefix = os.urandom(8)
        self._counter = 0
        self._pending = bytearray()
        fh.write(MAGIC + self._prefix)

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
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def decrypt_iter(path: str) -> Iterator[bytes]:
    """Yield the plaintext of an encrypted file record by record; raises FileCryptoError on any
    corruption (including truncation)."""
    key = _key()
    if key is None:
        raise FileCryptoError(
            "file is encrypted but no FILE_ENCRYPTION_KEY is configured"
        )
    aes = AESGCM(key)
    with open(path, "rb") as fh:
        if fh.read(len(MAGIC)) != MAGIC:
            raise FileCryptoError("not an encrypted file")
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
