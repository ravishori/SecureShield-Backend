"""Safe handling of user uploads and of the files they become.

Problems this removes (evidence + recordings both had them):
  * ``file.read()`` loaded the whole upload into memory with no size cap,
  * the client-supplied filename went straight into the on-disk path (path separators made
    the open() fail with a 500; odd characters ended up in headers and on disk),
  * stored paths were trusted when the file was served or deleted.
"""

from __future__ import annotations

import mimetypes
import os
import re
import uuid

from fastapi import HTTPException, UploadFile, status

CHUNK = 1024 * 1024
_UNSAFE = re.compile(r"[^A-Za-z0-9._\- ]")


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
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


async def save_upload(file: UploadFile, directory: str, *, default_name: str, max_bytes: int) -> tuple[str, int]:
    """Stream ``file`` to ``directory`` in chunks, enforcing ``max_bytes``.

    Returns ``(path, size)``. Raises 413 (too large) / 400 (empty); a partial file is removed."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{uuid.uuid4()}_{safe_filename(file.filename, default_name)}")
    size = 0
    try:
        with open(path, "wb") as out:
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File too large (maximum {max_bytes // (1024 * 1024)} MB).",
                    )
                out.write(chunk)
        if size == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded file is empty.")
    except BaseException:
        if os.path.exists(path):
            os.remove(path)
        raise
    return path, size


def save_text(directory: str, text: str, *, name: str) -> tuple[str, int]:
    """Persist generated text (e.g. an FIR draft) as a real file; returns ``(path, size)``."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{uuid.uuid4()}_{safe_filename(name, 'document.txt')}")
    data = text.encode("utf-8")
    with open(path, "wb") as f:
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found")
