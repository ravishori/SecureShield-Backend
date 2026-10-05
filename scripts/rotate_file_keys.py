"""Re-encrypt stored evidence/recording files under the ACTIVE encryption key.

    python scripts/rotate_file_keys.py --dry-run                 # report only
    python scripts/rotate_file_keys.py                           # rotate files written under older keys
    python scripts/rotate_file_keys.py --encrypt-plain           # also encrypt legacy plaintext files
    python scripts/rotate_file_keys.py uploads/evidence ...      # explicit directories

Key lifecycle (see app/services/file_crypto.py): add the new key to FILE_ENCRYPTION_KEYS, set
FILE_ENCRYPTION_ACTIVE_KEY_ID, deploy, run this script, verify the summary shows 0 files on old keys, THEN
remove the old keys from the configuration.

Safety: each file is rewritten to a temporary file in the same directory, the temporary file is decrypted and
compared (SHA-256) with the original plaintext, and only then does it atomically replace the original. A file that
cannot be read (corrupt, or its key is not configured) is left untouched and reported; the exit code is 2 if any
file failed. Run it while the API is stopped or at a quiet time: a download that races the replacement of one
file sees either the old or the new complete file, never a mix, but uploads should not be in flight.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import file_crypto as fc  # noqa: E402


def _plain_digest_encrypted(path: str) -> str:
    h = hashlib.sha256()
    for chunk in fc.decrypt_iter(path):
        h.update(chunk)
    return h.hexdigest()


def _raw_chunks(path: str):
    with open(path, "rb") as fh:
        while chunk := fh.read(fc.RECORD):
            yield chunk


def _plain_digest_raw(path: str) -> str:
    h = hashlib.sha256()
    for chunk in _raw_chunks(path):
        h.update(chunk)
    return h.hexdigest()


def rotate_file(path: str, active: tuple[int, bytes]) -> None:
    """Rewrite ``path`` under the active key (raises FileCryptoError / OSError on any problem)."""
    kid = fc.file_key_id(path)
    want = _plain_digest_raw(path) if kid is None else _plain_digest_encrypted(path)
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".rotate-")
    try:
        with os.fdopen(fd, "wb") as out:
            writer = fc.EncryptingWriter(out, active[1], active[0])
            source = _raw_chunks(path) if kid is None else fc.decrypt_iter(path)
            for chunk in source:
                writer.write(chunk)
            writer.close()
        if fc.file_key_id(tmp) != active[0] or _plain_digest_encrypted(tmp) != want:
            raise fc.FileCryptoError("verification of the re-encrypted copy failed")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "dirs", nargs="*", default=["uploads/evidence", "uploads/recordings"]
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--encrypt-plain",
        action="store_true",
        help="also encrypt files that are not encrypted yet",
    )
    args = ap.parse_args(argv)

    active = fc.active_key()
    if active is None:
        print("No encryption key configured: nothing to rotate to.", file=sys.stderr)
        return 1
    stats = {"rotated": 0, "already_current": 0, "plaintext_skipped": 0, "failed": 0}
    for d in args.dirs:
        for path in sorted(
            str(p)
            for p in Path(d).glob("*")
            if p.is_file() and not p.name.startswith(".rotate-")
        ):
            kid = fc.file_key_id(path)
            if kid == active[0]:
                stats["already_current"] += 1
                continue
            if kid is None and not args.encrypt_plain:
                stats["plaintext_skipped"] += 1
                continue
            if args.dry_run:
                stats["rotated"] += 1
                continue
            try:
                rotate_file(path, active)
                stats["rotated"] += 1
            except (fc.FileCryptoError, OSError) as exc:
                stats["failed"] += 1
                print(f"FAILED {os.path.basename(path)}: {exc}", file=sys.stderr)
    verb = "would rotate" if args.dry_run else "rotated"
    print(
        f"{verb}={stats['rotated']} already_current={stats['already_current']} "
        f"plaintext_skipped={stats['plaintext_skipped']} failed={stats['failed']} (active key id {active[0]})"
    )
    return 2 if stats["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
