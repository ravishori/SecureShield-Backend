"""Evidence + recordings (real files on disk, real DB rows) and admin error
log access control."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 64
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"1" * 128


@pytest.fixture(autouse=True)
def _upload_dirs(tmp_path, monkeypatch):
    import app.routers.evidence as ev
    import app.routers.recordings as rec

    for mod, name in ((ev, "evidence"), (rec, "recordings")):
        d = tmp_path / name
        d.mkdir()
        monkeypatch.setattr(mod, "UPLOAD_DIR", str(d))
    return tmp_path


async def test_evidence_upload_list_get_persist_file_and_are_user_scoped(
    client, make_user, auth_headers, _upload_dirs
):
    owner, other = await make_user("owner"), await make_user("other")
    r = await client.post(
        "/api/v1/evidence/upload",
        headers=auth_headers(owner),
        data={"title": "proof"},
        files={"file": ("p.png", PNG, "image/png")},
    )
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    assert [p.read_bytes() for p in (_upload_dirs / "evidence").iterdir()] == [PNG]

    listed = (await client.get("/api/v1/evidence/", headers=auth_headers(owner))).json()
    assert [e["id"] for e in listed] == [eid]
    assert (
        await client.get(f"/api/v1/evidence/{eid}", headers=auth_headers(owner))
    ).status_code == 200
    assert (
        await client.get("/api/v1/evidence/", headers=auth_headers(other))
    ).json() == []
    assert (
        await client.get(f"/api/v1/evidence/{eid}", headers=auth_headers(other))
    ).status_code in (403, 404)
    assert (await client.get("/api/v1/evidence/")).status_code in (401, 403)


async def test_recording_upload_list_share_download_roundtrip(
    client, make_user, auth_headers, _upload_dirs
):
    user, other = await make_user("rec"), await make_user("rec2")
    r = await client.post(
        "/api/v1/recordings/upload",
        headers=auth_headers(user),
        data={"title": "call", "duration_seconds": "3"},
        files={"file": ("r.mp4", MP4, "video/mp4")},
    )
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    assert len(list((_upload_dirs / "recordings").iterdir())) == 1

    listed = (
        await client.get("/api/v1/recordings/", headers=auth_headers(user))
    ).json()
    assert [x["id"] for x in listed] == [rid]
    assert (
        await client.get("/api/v1/recordings/", headers=auth_headers(other))
    ).json() == []

    # another user cannot mint a share link for it
    forbidden = await client.post(
        f"/api/v1/recordings/{rid}/share-link", headers=auth_headers(other)
    )
    assert forbidden.status_code in (403, 404)
    s = await client.post(
        f"/api/v1/recordings/{rid}/share-link", headers=auth_headers(user)
    )
    assert s.status_code == 200
    d = await client.get(s.json()["share_url"])
    assert d.status_code == 200 and d.content == MP4
    assert (
        await client.get("/api/v1/recordings/share/not-a-real-token")
    ).status_code in (403, 404)


async def test_admin_errors_requires_the_admin_token(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ADMIN_TOKEN", "unit-test-admin-token-xyz")
    url = "/api/v1/admin/errors"
    assert (await client.get(url)).status_code in (401, 403)
    assert (await client.get(url, headers={"X-Admin-Token": "wrong"})).status_code in (
        401,
        403,
    )
    ok = await client.get(url, headers={"X-Admin-Token": "unit-test-admin-token-xyz"})
    assert ok.status_code == 200 and "errors" in ok.json()


async def test_admin_errors_disabled_when_token_unset(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    r = await client.get("/api/v1/admin/errors", headers={"X-Admin-Token": ""})
    assert r.status_code in (401, 403, 503)
