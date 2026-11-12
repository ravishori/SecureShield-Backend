"""The admin console is one inline script served from a Python string: an escaping slip (a raw newline inside a JS string)
silently breaks the whole page, so the script is syntax-checked with Node when it is available."""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from app.routers import admin_console

SCRIPT = re.search(r"<script>(.*)</script>", admin_console.PAGE, re.S).group(1)


def test_no_raw_newline_inside_a_double_quoted_js_string():
    for n, line in enumerate(SCRIPT.splitlines(), 1):
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
        assert stripped.count('"') % 2 == 0, (
            f"unterminated string on script line {n}: {line[:80]}"
        )


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_console_script_parses():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "console.js"
        f.write_text(SCRIPT, encoding="utf-8")
        r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_page_never_persists_credentials():
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "location.hash",
        "location.search",
    ):
        assert forbidden not in admin_console.PAGE
