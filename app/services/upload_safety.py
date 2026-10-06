"""Safe handling of user uploads and of the files they become.

Problems this removes (evidence + recordings both had them):
  * ``file.read()`` loaded the whole upload into memory with no size cap,
  * the client-supplied filename went straight into the on-disk path (path separators made
    the open() fail with a 500; odd characters ended up in headers and on disk),
  * stored paths were trusted when the file was served or deleted,
  * any file type was accepted (HTML/SVG/scripts/executables) and the served ``Content-Type`` was guessed from the
    client-chosen name, so the public share link could hand out active content.

Type policy: an upload must have an allow-listed extension AND its first bytes must match that format
(``UploadPolicy``). Downloads use a fixed extension -> media-type table and fall back to
``application/octet-stream``; HTML/SVG/script types can never be served inline or with a markup type.
This is a type/consistency check, not malware scanning (no AV engine is available; see FG-071).
"""

from __future__ import annotations

import os
import re
import uuid

from fastapi import HTTPException, UploadFile, status
from fastapi.responses import FileResponse, StreamingResponse

from app.services import file_crypto

CHUNK = 1024 * 1024
_UNSAFE = re.compile(r"[^A-Za-z0-9._\- ]")

_ISO_BMFF = (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip")


def _riff(kind: bytes):
    return lambda h: h[:4] == b"RIFF" and h[8:12] == kind


def _iso_bmff(h: bytes) -> bool:
    return h[4:8] in _ISO_BMFF


def _mp3(h: bytes) -> bool:
    return h[:3] == b"ID3" or (len(h) > 1 and h[0] == 0xFF and (h[1] & 0xE0) == 0xE0)


def _aac(h: bytes) -> bool:
    return _iso_bmff(h) or _mp3(h)  # ADTS frame sync is covered by _mp3's 0xFFEx check


def _text(h: bytes) -> bool:
    return b"\x00" not in h


_JPEG = b"\xff\xd8\xff"
_PNG = b"\x89PNG\r\n\x1a\n"
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_EBML = b"\x1a\x45\xdf\xa3"

# extension -> (served media type, header check). Anything not listed is rejected on upload and is served
# as application/octet-stream if it is already stored.
FORMATS: dict[str, tuple[str, object]] = {
    "jpg": ("image/jpeg", lambda h: h[:3] == _JPEG),
    "jpeg": ("image/jpeg", lambda h: h[:3] == _JPEG),
    "png": ("image/png", lambda h: h[:8] == _PNG),
    "gif": ("image/gif", lambda h: h[:4] == b"GIF8"),
    "webp": ("image/webp", lambda h: h[:4] == b"RIFF" and h[8:12] == b"WEBP"),
    "bmp": ("image/bmp", lambda h: h[:2] == b"BM"),
    "heic": ("image/heic", lambda h: h[4:8] == b"ftyp"),
    "pdf": ("application/pdf", lambda h: b"%PDF-" in h[:1024]),
    "txt": ("text/plain", _text),
    "doc": ("application/msword", lambda h: h[:8] == _OLE),
    "docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        lambda h: h[:4] == b"PK\x03\x04",
    ),
    "mp3": ("audio/mpeg", _mp3),
    "wav": ("audio/wav", _riff(b"WAVE")),
    "aac": ("audio/aac", _aac),
    "m4a": ("audio/mp4", _iso_bmff),
    "ogg": ("audio/ogg", lambda h: h[:4] == b"OggS"),
    "mp4": ("video/mp4", _iso_bmff),
    "mov": ("video/quicktime", _iso_bmff),
    "3gp": ("video/3gpp", _iso_bmff),
    "avi": ("video/x-msvideo", _riff(b"AVI ")),
    "mkv": ("video/x-matroska", lambda h: h[:4] == _EBML),
    "webm": ("video/webm", lambda h: h[:4] == _EBML),
}

IMAGES = {"jpg", "jpeg", "png", "gif", "webp", "bmp", "heic"}
AUDIO = {"mp3", "wav", "aac", "m4a", "ogg"}
VIDEO = {"mp4", "mov", "3gp", "avi", "mkv", "webm"}
DOCUMENTS = {"pdf", "txt", "doc", "docx"}


class UploadPolicy:
    """Which extensions an endpoint accepts. Content is always checked against ``FORMATS``."""

    def __init__(self, name: str, extensions: set[str]):
        self.name = name
        self.extensions = frozenset(extensions)


EVIDENCE_POLICY = UploadPolicy("evidence", IMAGES | AUDIO | VIDEO | DOCUMENTS)
RECORDING_POLICY = UploadPolicy("recording", AUDIO | VIDEO)


def extension_of(name: str | None) -> str:
    base = os.path.basename((name or "").replace("\\", "/"))
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def check_extension(filename: str | None, policy: UploadPolicy) -> str:
    ext = extension_of(filename)
    if ext not in policy.extensions:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"This file type is not accepted for {policy.name} uploads.",
        )
    return ext


def check_content(ext: str, head: bytes) -> None:
    """The first bytes must look like the format the extension claims (blocks e.g. HTML saved as .png)."""
    if not FORMATS[ext][1](head):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="The file content does not match its file type.",
        )


def safe_filename(name: str | None, default: str = "file", max_len: int = 100) -> str:
    """A filename that cannot contain a path, control characters or header-hostile characters."""
    base = os.path.basename((name or "").replace("\\", "/")).strip()
    base = _UNSAFE.sub("_", base).strip(" .")
    if not base:
        base = default
    if len(base) > max_len:
        stem, ext = os.path.splitext(base)
        base = stem[: max_len - len(ext)] + ext
    return base


def display_name(stored_path: str) -> str:
    """Original (sanitised) filename from a stored ``<uuid>_<name>`` path."""
    base = os.path.basename(stored_path)
    return base.split("_", 1)[1] if "_" in base else base


def guess_media_type(filename: str) -> str:
    """Media type from a FIXED table (never from the OS/mimetypes registry, which maps html/svg/js to active types)."""
    entry = FORMATS.get(extension_of(filename))
    return entry[0] if entry else "application/octet-stream"


async def save_upload(
    file: UploadFile,
    directory: str,
    *,
    default_name: str,
    max_bytes: int,
    policy: UploadPolicy | None = None,
) -> tuple[str, int]:
    """Stream ``file`` to ``directory`` in chunks, enforcing ``max_bytes``.

    Returns ``(path, size)``. Raises 415 (type not allowed / content mismatch), 413 (too large) or 400 (empty);
    a partial file is removed. With a ``policy`` the stored name always carries the validated extension."""
    ext = check_extension(file.filename or default_name, policy) if policy else None
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(
        directory, f"{uuid.uuid4()}_{safe_filename(file.filename, default_name)}"
    )
    size = 0
    active = file_crypto.active_key()
    key = active[1] if active else None
    try:
        with open(path, "wb") as raw:
            out = (
                file_crypto.EncryptingWriter(raw, active[1], active[0])
                if active
                else raw
            )
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                if ext and size == 0:
                    check_content(ext, chunk[:4096])
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File too large (maximum {max_bytes // (1024 * 1024)} MB).",
                    )
                out.write(chunk)
            if key and size:
                out.close()
        if size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The uploaded file is empty.",
            )
    except BaseException:
        if os.path.exists(path):
            os.remove(path)
        raise
    return path, size


def save_text(directory: str, text: str, *, name: str) -> tuple[str, int]:
    """Persist generated text (e.g. an FIR draft) as a real file; returns ``(path, size)``."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(
        directory, f"{uuid.uuid4()}_{safe_filename(name, 'document.txt')}"
    )
    data = text.encode("utf-8")
    active = file_crypto.active_key()
    with open(path, "wb") as f:
        if active:
            writer = file_crypto.EncryptingWriter(f, active[1], active[0])
            writer.write(data)
            writer.close()
        else:
            f.write(data)
    return path, len(data)


def resolve_inside(directory: str, stored_path: str) -> str | None:
    """Absolute path of ``stored_path`` if (and only if) it is an existing file inside ``directory``."""
    root = os.path.abspath(directory)
    full = os.path.abspath(stored_path)
    if full.startswith(root + os.sep) and os.path.isfile(full):
        return full
    return None


def parse_uuid_or_404(value: str, what: str = "Resource") -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found"
        )


def file_download_response(path: str, name: str) -> FileResponse | StreamingResponse:
    """Serve a stored file as an attachment, decrypting it on the fly when it is encrypted at rest.

    The first record is decrypted before any response bytes are sent so a corrupt/tampered file or a
    wrong key becomes a clean HTTP error instead of a broken half-download."""
    headers = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    media_type = guess_media_type(name)
    if not file_crypto.is_encrypted_file(path):
        return FileResponse(
            path,
            media_type=media_type,
            filename=name,
            headers=headers,
            content_disposition_type="attachment",
        )
    try:
        chunks = file_crypto.decrypt_iter(path)
        first = next(chunks, b"")
    except file_crypto.FileCryptoError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The stored file could not be read.",
        )

    def stream():
        yield first
        yield from chunks

    quoted = name.replace('"', "")
    headers["Content-Disposition"] = f'attachment; filename="{quoted}"'
    return StreamingResponse(stream(), media_type=media_type, headers=headers)
