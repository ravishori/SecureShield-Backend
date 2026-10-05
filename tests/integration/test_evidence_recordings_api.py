"""Evidence locker + recordings: safe uploads, ownership, downloads, share-link lifecycle.
Real files on disk (tmp dirs), real PostgreSQL rows."""

import pytest
from sqlalchemy import select, text

from app.models.evidence import Evidence
from app.models.recording import Recording

pytestmark = pytest.mark.integration

EV = "/api/v1/evidence"
REC = "/api/v1/recordings"
PNG = b"\x89PNG\r\n\x1a\n" + b"E" * 100
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"R" * 200


@pytest.fixture(autouse=True)
def _dirs(tmp_path, monkeypatch):
    import app.routers.evidence as ev
    import app.routers.recordings as rec

    for mod, name in ((ev, "evidence"), (rec, "recordings")):
        d = tmp_path / name
        d.mkdir()
        monkeypatch.setattr(mod, "UPLOAD_DIR", str(d))
    return tmp_path


def files_in(tmp, kind):
    return sorted((tmp / kind).iterdir())


async def up_ev(client, h, name="e.png", data=PNG, **form):
    return await client.post(
        f"{EV}/upload",
        headers=h,
        data={"title": "t", **form},
        files={"file": (name, data, "application/octet-stream")},
    )


async def up_rec(client, h, name="r.mp4", data=MP4, **form):
    return await client.post(
        f"{REC}/upload",
        headers=h,
        data={"title": "t", "duration_seconds": "3", **form},
        files={"file": (name, data, "video/mp4")},
    )


# ───────────────────────────────── evidence ─────────────────────────────────
async def test_upload_hides_server_path_and_offers_download(
    client, make_user, auth_headers, _dirs
):
    u = await make_user("ev")
    r = await up_ev(client, auth_headers(u), name="Screenshot 1.png")
    assert r.status_code == 200, r.text
    j = r.json()
    assert "file_path" not in j and j["filename"] == "Screenshot 1.png"
    assert j["download_url"] == f"/api/v1/evidence/{j['id']}/download" and j[
        "file_size_bytes"
    ] == len(PNG)
    assert len(files_in(_dirs, "evidence")) == 1


@pytest.mark.security
@pytest.mark.parametrize(
    "hostile",
    [
        "../../../etc/passwd",
        "..\\..\\win.ini",
        "a/b/c.png",
        "/abs/path.png",
        "na\x00me.png",
        "x" * 400 + ".png",
        "con?*.png",
        "   ",
        "..",
    ],
)
async def test_hostile_filenames_cannot_escape_the_upload_dir(
    client, make_user, auth_headers, _dirs, hostile
):
    h = auth_headers(await make_user("hf"))
    r = await up_ev(client, h, name=hostile)
    assert r.status_code == 200, r.text
    stored = files_in(_dirs, "evidence")
    assert len(stored) == 1 and stored[0].parent == _dirs / "evidence"
    assert (
        not any(c in stored[0].name for c in "/\\:*?\x00") and len(stored[0].name) < 200
    )
    assert list(_dirs.glob("*.png")) == [] and not (_dirs.parent / "passwd").exists()


async def test_size_cap_returns_413_and_leaves_no_partial_file(
    client, make_user, auth_headers, _dirs, monkeypatch
):
    from app.config import settings

    monkeypatch.setattr(settings, "MAX_EVIDENCE_MB", 1)
    h = auth_headers(await make_user("big"))
    r = await up_ev(client, h, data=b"x" * (1024 * 1024 + 10))
    assert r.status_code == 413
    assert files_in(_dirs, "evidence") == []
    assert (await up_ev(client, h, data=b"x" * 1000)).status_code == 200


async def test_empty_upload_is_rejected(client, make_user, auth_headers, _dirs):
    assert (
        await up_ev(client, auth_headers(await make_user("emp")), data=b"")
    ).status_code == 400
    assert files_in(_dirs, "evidence") == []


@pytest.mark.parametrize(
    "form",
    [
        {"title": ""},
        {"title": "t" * 201},
        {"description": "d" * 2001},
        {"case_id": "c" * 65},
    ],
)
async def test_form_fields_are_bounded(client, make_user, auth_headers, form):
    h = auth_headers(await make_user("ff"))
    data = {"title": "ok", **form}
    r = await client.post(
        f"{EV}/upload",
        headers=h,
        data=data,
        files={"file": ("a.png", PNG, "image/png")},
    )
    assert r.status_code == 422


async def test_owner_downloads_exact_bytes_as_attachment(
    client, make_user, auth_headers
):
    h = auth_headers(await make_user("dl"))
    j = (await up_ev(client, h, name="proof.png")).json()
    d = await client.get(j["download_url"], headers=h)
    assert d.status_code == 200 and d.content == PNG
    assert (
        "attachment" in d.headers["content-disposition"]
        and "proof.png" in d.headers["content-disposition"]
    )
    assert (
        d.headers["x-content-type-options"] == "nosniff"
        and d.headers["cache-control"] == "no-store"
    )
    assert d.headers["content-type"].startswith("image/png")


async def test_download_is_owner_only_and_authenticated(
    client, make_user, auth_headers
):
    owner, other = await make_user("o"), await make_user("x")
    j = (await up_ev(client, auth_headers(owner))).json()
    assert (
        await client.get(j["download_url"], headers=auth_headers(other))
    ).status_code == 404
    assert (await client.get(j["download_url"])).status_code in (401, 403)
    assert (
        await client.get(f"{EV}/{j['id']}", headers=auth_headers(other))
    ).status_code == 404


async def test_invalid_ids_are_404_not_500(client, make_user, auth_headers):
    h = auth_headers(await make_user("id"))
    for path in ("not-a-uuid", "not-a-uuid/download"):
        assert (await client.get(f"{EV}/{path}", headers=h)).status_code == 404
    assert (await client.delete(f"{EV}/not-a-uuid", headers=h)).status_code == 404


@pytest.mark.security
async def test_tampered_db_path_outside_the_upload_dir_is_never_served_or_deleted(
    client, make_user, auth_headers, session_factory, _dirs
):
    u = await make_user("tamper")
    h = auth_headers(u)
    secret = _dirs / "outside-secret.txt"
    secret.write_text("TOP-SECRET")
    async with session_factory() as s:
        e = Evidence(
            user_id=u.id,
            title="t",
            file_path=str(secret),
            file_type="document",
            file_size_bytes=10,
        )
        s.add(e)
        await s.commit()
        eid = str(e.id)
    assert (await client.get(f"{EV}/{eid}/download", headers=h)).status_code == 404
    assert (await client.delete(f"{EV}/{eid}", headers=h)).status_code == 200
    assert secret.exists() and secret.read_text() == "TOP-SECRET"


async def test_missing_file_on_disk_gives_404_on_download_and_clean_delete(
    client, make_user, auth_headers, _dirs
):
    h = auth_headers(await make_user("gone"))
    j = (await up_ev(client, h)).json()
    for p in files_in(_dirs, "evidence"):
        p.unlink()
    assert (await client.get(j["download_url"], headers=h)).status_code == 404
    assert (await client.delete(f"{EV}/{j['id']}", headers=h)).status_code == 200


async def test_delete_removes_row_and_file(client, make_user, auth_headers, _dirs, db):
    h = auth_headers(await make_user("del"))
    j = (await up_ev(client, h)).json()
    assert (await client.delete(f"{EV}/{j['id']}", headers=h)).status_code == 200
    assert files_in(_dirs, "evidence") == []
    assert (await db.execute(select(Evidence))).scalars().all() == []


# ──────────────────────────────── recordings ────────────────────────────────
async def test_recording_upload_list_and_owner_download(
    client, make_user, auth_headers, _dirs
):
    h = auth_headers(await make_user("rec"))
    r = await up_rec(client, h, name="call 1.mp4")
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    assert [x["id"] for x in (await client.get(f"{REC}/", headers=h)).json()] == [rid]
    d = await client.get(f"{REC}/{rid}/download", headers=h)
    assert d.status_code == 200 and d.content == MP4
    assert (
        d.headers["content-type"].startswith("video/mp4")
        and "attachment" in d.headers["content-disposition"]
    )


@pytest.mark.security
async def test_recording_hostile_names_size_cap_and_bounds(
    client, make_user, auth_headers, _dirs, monkeypatch
):
    from app.config import settings

    h = auth_headers(await make_user("rh"))
    assert (await up_rec(client, h, name="../../evil.mp4")).status_code == 200
    stored = files_in(_dirs, "recordings")
    assert len(stored) == 1 and stored[0].parent == _dirs / "recordings"
    monkeypatch.setattr(settings, "MAX_RECORDING_MB", 1)
    assert (await up_rec(client, h, data=b"x" * (1024 * 1024 + 5))).status_code == 413
    assert len(files_in(_dirs, "recordings")) == 1  # no partial file
    assert (await up_rec(client, h, duration_seconds="-5")).status_code == 422
    assert (await up_rec(client, h, duration_seconds="99999999")).status_code == 422


async def test_recording_downloads_are_owner_only(client, make_user, auth_headers):
    owner, other = await make_user("ro"), await make_user("rx")
    rid = (await up_rec(client, auth_headers(owner))).json()["id"]
    assert (
        await client.get(f"{REC}/{rid}/download", headers=auth_headers(other))
    ).status_code == 404
    assert (await client.get(f"{REC}/{rid}/download")).status_code in (401, 403)
    assert (
        await client.delete(f"{REC}/{rid}", headers=auth_headers(other))
    ).status_code == 404
    assert (
        await client.post(f"{REC}/{rid}/share-link", headers=auth_headers(other))
    ).status_code == 404
    assert (
        await client.get(f"{REC}/not-a-uuid/download", headers=auth_headers(owner))
    ).status_code == 404


async def test_share_link_serves_correct_type_with_safe_headers(
    client, make_user, auth_headers
):
    h = auth_headers(await make_user("sh"))
    rid = (await up_rec(client, h, name="clip.mp4")).json()["id"]
    url = (await client.post(f"{REC}/{rid}/share-link", headers=h)).json()["share_url"]
    d = await client.get(url)  # public: no auth by design
    assert d.status_code == 200 and d.content == MP4
    assert d.headers["content-type"].startswith(
        "video/mp4"
    )  # was hard-coded audio/aac for everything
    assert (
        d.headers["x-content-type-options"] == "nosniff"
        and d.headers["cache-control"] == "no-store"
    )


async def test_share_link_can_be_revoked_expired_links_are_410_unknown_404(
    client, make_user, auth_headers, session_factory
):
    h = auth_headers(await make_user("rv"))
    rid = (await up_rec(client, h)).json()["id"]
    url = (await client.post(f"{REC}/{rid}/share-link", headers=h)).json()["share_url"]
    assert (await client.get(url)).status_code == 200
    assert (
        await client.delete(f"{REC}/{rid}/share-link", headers=h)
    ).status_code == 200
    assert (await client.get(url)).status_code == 404  # revoked
    url2 = (await client.post(f"{REC}/{rid}/share-link", headers=h)).json()["share_url"]
    async with session_factory() as s:
        await s.execute(
            text(
                "update recordings set share_expires_at = (now() at time zone 'utc') - interval '1 minute'"
            )
        )
        await s.commit()
    assert (await client.get(url2)).status_code == 410
    assert (await client.get(f"{REC}/share/definitely-not-a-token")).status_code == 404


async def test_recording_delete_removes_row_file_and_share_link(
    client, make_user, auth_headers, _dirs, db
):
    h = auth_headers(await make_user("rd"))
    rid = (await up_rec(client, h)).json()["id"]
    url = (await client.post(f"{REC}/{rid}/share-link", headers=h)).json()["share_url"]
    assert (await client.delete(f"{REC}/{rid}", headers=h)).status_code == 200
    assert (
        files_in(_dirs, "recordings") == []
        and (await client.get(url)).status_code == 404
    )
    assert (await db.execute(select(Recording))).scalars().all() == []
