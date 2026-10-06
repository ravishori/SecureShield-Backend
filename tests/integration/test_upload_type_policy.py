"""FG-071: upload type policy (extension allow-list + content/extension consistency) and safe served media types."""

import pytest

from app.models.evidence import Evidence
from app.services import upload_safety as us

pytestmark = pytest.mark.integration

EV = "/api/v1/evidence"
REC = "/api/v1/recordings"

SAMPLES = {
    "jpg": b"\xff\xd8\xff\xe0" + b"j" * 40,
    "jpeg": b"\xff\xd8\xff\xe1" + b"j" * 40,
    "png": b"\x89PNG\r\n\x1a\n" + b"p" * 40,
    "gif": b"GIF89a" + b"g" * 40,
    "webp": b"RIFF\x10\x00\x00\x00WEBPVP8 " + b"w" * 20,
    "bmp": b"BM" + b"b" * 40,
    "heic": b"\x00\x00\x00\x18ftypheic" + b"h" * 20,
    "pdf": b"%PDF-1.7\n" + b"d" * 40,
    "txt": b"plain text evidence\n",
    "doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"o" * 40,
    "docx": b"PK\x03\x04" + b"z" * 40,
    "mp3": b"ID3\x03\x00" + b"m" * 40,
    "wav": b"RIFF\x10\x00\x00\x00WAVEfmt " + b"v" * 20,
    "aac": b"\xff\xf1\x50\x80" + b"a" * 40,
    "m4a": b"\x00\x00\x00\x18ftypM4A " + b"a" * 20,
    "ogg": b"OggS\x00\x02" + b"o" * 40,
    "mp4": b"\x00\x00\x00\x18ftypmp42" + b"v" * 20,
    "mov": b"\x00\x00\x00\x14ftypqt  " + b"v" * 20,
    "3gp": b"\x00\x00\x00\x14ftyp3gp4" + b"v" * 20,
    "avi": b"RIFF\x10\x00\x00\x00AVI LIST" + b"v" * 20,
    "mkv": b"\x1a\x45\xdf\xa3" + b"k" * 40,
    "webm": b"\x1a\x45\xdf\xa3" + b"k" * 40,
}
HTML = b"<!DOCTYPE html><html><script>alert(1)</script></html>"


@pytest.fixture(autouse=True)
def _dirs(tmp_path, monkeypatch):
    import app.routers.evidence as ev
    import app.routers.recordings as rec

    for mod, name in ((ev, "evidence"), (rec, "recordings")):
        d = tmp_path / name
        d.mkdir()
        monkeypatch.setattr(mod, "UPLOAD_DIR", str(d))
    return tmp_path


def stored(tmp, kind):
    return sorted((tmp / kind).iterdir())


async def up(client, h, kind, name, data):
    url = f"{EV}/upload" if kind == "evidence" else f"{REC}/upload"
    form = {"title": "t"} | ({"duration_seconds": "3"} if kind == "recordings" else {})
    return await client.post(
        url, headers=h, data=form, files={"file": (name, data, "text/html")}
    )


# ---------------------------------------------------------------- allowed formats
@pytest.mark.parametrize("ext", sorted(us.EVIDENCE_POLICY.extensions))
async def test_every_allowed_evidence_format_is_accepted(
    client, make_user, auth_headers, _dirs, ext
):
    h = auth_headers(await make_user("ok" + ext))
    r = await up(client, h, "evidence", f"proof.{ext}", SAMPLES[ext])
    assert r.status_code == 200, r.text
    assert len(stored(_dirs, "evidence")) == 1


@pytest.mark.parametrize("ext", sorted(us.RECORDING_POLICY.extensions))
async def test_every_allowed_recording_format_is_accepted(
    client, make_user, auth_headers, _dirs, ext
):
    h = auth_headers(await make_user("okr" + ext))
    r = await up(client, h, "recordings", f"call.{ext}", SAMPLES[ext])
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------- rejected types
@pytest.mark.security
@pytest.mark.parametrize(
    "name",
    [
        "page.html",
        "page.HTM",
        "image.svg",
        "script.js",
        "run.exe",
        "app.apk",
        "shell.php",
        "run.sh",
        "run.bat",
        "lib.jar",
        "data.xml",
        "archive.zip",
        "noextension",
        "dotfile.",
    ],
)
@pytest.mark.parametrize("kind", ["evidence", "recordings"])
async def test_active_or_unknown_types_are_rejected_and_nothing_is_stored(
    client, make_user, auth_headers, _dirs, name, kind
):
    h = auth_headers(await make_user("bad"))
    r = await up(client, h, kind, name, HTML)
    assert r.status_code == 415, r.text
    assert stored(_dirs, kind) == []


@pytest.mark.security
@pytest.mark.parametrize("kind", ["evidence", "recordings"])
async def test_markup_disguised_with_an_allowed_extension_is_rejected(
    client, make_user, auth_headers, _dirs, kind
):
    h = auth_headers(await make_user("dis"))
    names = ["x.png", "x.mp4", "x.html.png", "x.php.mp4", "x.pdf", "x.mp3"]
    for name in names:
        ext = us.extension_of(name)
        if kind == "recordings" and ext not in us.RECORDING_POLICY.extensions:
            continue
        r = await up(client, h, kind, name, HTML)
        assert r.status_code == 415, (name, r.text)
    assert stored(_dirs, kind) == []


@pytest.mark.security
async def test_format_mismatch_between_extension_and_content_is_rejected(
    client, make_user, auth_headers, _dirs
):
    h = auth_headers(await make_user("mm"))
    assert (await up(client, h, "evidence", "a.png", SAMPLES["pdf"])).status_code == 415
    assert (await up(client, h, "evidence", "a.pdf", SAMPLES["png"])).status_code == 415
    assert (await up(client, h, "evidence", "a.txt", b"abc\x00def")).status_code == 415
    assert stored(_dirs, "evidence") == []


async def test_evidence_only_types_are_not_accepted_as_recordings(
    client, make_user, auth_headers, _dirs
):
    h = auth_headers(await make_user("rc"))
    for ext in ("pdf", "png", "docx", "txt"):
        r = await up(client, h, "recordings", f"x.{ext}", SAMPLES[ext])
        assert r.status_code == 415, ext
    assert stored(_dirs, "recordings") == []


async def test_uppercase_extension_is_accepted_and_still_content_checked(
    client, make_user, auth_headers, _dirs
):
    h = auth_headers(await make_user("up"))
    assert (
        await up(client, h, "evidence", "IMG.PNG", SAMPLES["png"])
    ).status_code == 200
    assert (await up(client, h, "evidence", "IMG2.PNG", HTML)).status_code == 415


# ---------------------------------------------------------------- serving
@pytest.mark.security
@pytest.mark.parametrize(
    "name,expected",
    [
        ("a.html", "application/octet-stream"),
        ("a.htm", "application/octet-stream"),
        ("a.svg", "application/octet-stream"),
        ("a.js", "application/octet-stream"),
        ("a.xml", "application/octet-stream"),
        ("a", "application/octet-stream"),
        ("a.PNG", "image/png"),
        ("a.mp4", "video/mp4"),
        ("a.pdf", "application/pdf"),
    ],
)
def test_served_media_type_comes_from_a_fixed_table(name, expected):
    assert us.guess_media_type(name) == expected


@pytest.mark.security
async def test_legacy_stored_html_is_served_as_an_octet_stream_attachment(
    client, make_user, auth_headers, session_factory, _dirs
):
    """A file stored before the policy existed (e.g. page.html) must never be handed back as markup."""
    u = await make_user("legacy")
    h = auth_headers(u)
    path = _dirs / "evidence" / "11111111-1111-1111-1111-111111111111_page.html"
    path.write_bytes(HTML)
    async with session_factory() as s:
        e = Evidence(
            user_id=u.id,
            title="t",
            file_path=str(path),
            file_type="document",
            file_size_bytes=len(HTML),
        )
        s.add(e)
        await s.commit()
        eid = str(e.id)
    r = await client.get(f"{EV}/{eid}/download", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/octet-stream")
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["x-content-type-options"] == "nosniff"


# ---------------------------------------------------------------- unit: header checks
@pytest.mark.parametrize("ext", sorted(us.FORMATS))
def test_every_format_accepts_its_sample_and_rejects_markup(ext):
    us.check_content(ext, SAMPLES[ext])
    if ext == "txt":  # text has no signature; binary content is what is rejected
        with pytest.raises(us.HTTPException):
            us.check_content(ext, b"a\x00b")
        return
    with pytest.raises(us.HTTPException) as e:
        us.check_content(ext, HTML)
    assert e.value.status_code == 415


def test_no_active_content_type_can_ever_be_served():
    served = {mt for mt, _ in us.FORMATS.values()}
    active = {
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
        "text/javascript",
        "application/javascript",
        "application/xml",
        "text/xml",
        "application/x-sh",
        "application/x-msdownload",
        "application/vnd.android.package-archive",
    }
    assert not (served & active)
    assert not (
        {"html", "htm", "svg", "js", "xml", "php", "exe", "apk"} & set(us.FORMATS)
    )
