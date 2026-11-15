"""DELETE /auth/me: genuine erasure of user data + explicit retention policy.

Real PostgreSQL, real files on disk, real routes. Every user-linked table is populated
for the victim and for a bystander; the bystander's data must be untouched."""

import datetime as dt
import enum
import uuid

import pytest
from tests.integration.conftest import delete_body
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from app.models.ai_conversation import AiConversation
from app.models.alert import Alert
from app.models.app_install_event import AppInstallEvent
from app.models.app_scan import AppScan
from app.models.behavior_event import BehaviorEvent
from app.models.clone_report import CloneReport
from app.models.community_scam import CommunityScamReport
from app.models.cyber_warrior import (
    ApplicationStatus,
    AuditAction,
    WarriorApplication,
    WarriorAuditLog,
    WarriorProfile,
    WarriorRole,
)
from app.models.device import Device
from app.models.elderly_config import ElderlyConfig
from app.models.emergency_contact import EmergencyContact
from app.models.error_log import ErrorLog
from app.models.evidence import Evidence
from app.models.family import FamilyMember
from app.models.link_scan import LinkScan
from app.models.network_activity import NetworkActivity
from app.models.recording import Recording
from app.models.scam_call import ScamCall
from app.models.security_report import SecurityReport
from app.models.user import OTP, User
from app.models.wifi_scan import WifiScan

pytestmark = pytest.mark.integration

ME = "/api/v1/auth/me"
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 64
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"1" * 128


def _dummy(col):
    t = col.type
    if isinstance(t, ARRAY):
        return []
    if isinstance(t, JSONB) or t.__class__.__name__ in ("JSON", "JSONB"):
        return {}
    if hasattr(t, "enums") and t.enums:
        enum_cls = getattr(t, "enum_class", None)
        return list(enum_cls)[0] if enum_cls else t.enums[0]
    py = getattr(t, "python_type", None)
    try:
        py = t.python_type
    except NotImplementedError:
        py = str
    if py is uuid.UUID:
        return uuid.uuid4()
    if py is bool:
        return False
    if py is int:
        return 1
    if py is float:
        return 0.0
    if py is dt.datetime:
        return dt.datetime.utcnow()
    if py is dt.date:
        return dt.date(1990, 1, 1)
    if issubclass(py, enum.Enum):
        return list(py)[0]
    return uuid.uuid4().hex[:8]


def make_row(model, **given):
    """Instantiate ``model`` with dummy values for every required column."""
    values = dict(given)
    for col in sa_inspect(model).columns:
        if col.key in values:
            continue
        if col.nullable or col.server_default is not None or col.default is not None:
            continue
        if col.primary_key and col.autoincrement:
            continue
        values[col.key] = _dummy(col)
    return model(**values)


@pytest.fixture(autouse=True)
def _upload_dirs(tmp_path, monkeypatch):
    import app.routers.evidence as ev
    import app.routers.recordings as rec

    for mod, name in ((ev, "evidence"), (rec, "recordings")):
        d = tmp_path / name
        d.mkdir()
        monkeypatch.setattr(mod, "UPLOAD_DIR", str(d))
    return tmp_path


async def _populate(session_factory, client, headers, user, upload_dirs):
    """Give ``user`` data in every user-linked table; returns identifiers for assertions."""
    info = {}

    def listing():
        return {
            p for d in ("evidence", "recordings") for p in (upload_dirs / d).iterdir()
        }

    before = listing()
    r = await client.post(
        "/api/v1/evidence/upload",
        headers=headers,
        data={"title": "ev"},
        files={"file": ("e.png", PNG, "image/png")},
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        "/api/v1/recordings/upload",
        headers=headers,
        data={"title": "rec", "duration_seconds": "3"},
        files={"file": ("r.mp4", MP4, "video/mp4")},
    )
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    sh = await client.post(f"/api/v1/recordings/{rid}/share-link", headers=headers)
    assert sh.status_code == 200
    info["share_url"] = sh.json()["share_url"]
    info["files"] = sorted(listing() - before)
    assert len(info["files"]) == 2

    async with session_factory() as s:
        device = make_row(Device, user_id=user.id)
        s.add(device)
        await s.flush()
        s.add_all(
            [
                make_row(Alert, user_id=user.id, device_id=device.id),
                make_row(NetworkActivity, device_id=device.id),
                make_row(AppScan, device_id=device.id),
                make_row(WifiScan, device_id=device.id),
                make_row(AiConversation, user_id=user.id),
                make_row(AppInstallEvent, user_id=user.id),
                make_row(BehaviorEvent, user_id=user.id),
                make_row(CloneReport, user_id=user.id),
                make_row(CommunityScamReport, user_id=user.id),
                make_row(
                    EmergencyContact,
                    user_id=user.id,
                    phone="+919800000001",
                    email="ec@example.com",
                ),
                make_row(
                    ElderlyConfig,
                    user_id=user.id,
                    guardian_phone="+919800000002",
                    guardian_email="g@example.com",
                ),
                make_row(LinkScan, user_id=user.id),
                make_row(ScamCall, user_id=user.id),
                make_row(SecurityReport, user_id=user.id),
                make_row(FamilyMember, user_id=user.id),
                make_row(
                    OTP,
                    email=user.email,
                    phone=user.phone,
                    code="123456",
                    expires_at=dt.datetime.utcnow() + dt.timedelta(minutes=5),
                ),
            ]
        )
        # Cyber Warrior data + an audit trail row that MUST survive
        app_row = make_row(
            WarriorApplication, user_id=user.id, status=ApplicationStatus.approved
        )
        s.add(app_row)
        await s.flush()
        s.add(
            make_row(
                WarriorProfile,
                user_id=user.id,
                application_id=app_row.id,
                role=WarriorRole.trainee,
            )
        )
        s.add(
            make_row(
                WarriorAuditLog,
                actor_user_id=user.id,
                subject_user_id=user.id,
                action=AuditAction.application_approved,
            )
        )
        s.add(make_row(ErrorLog, user_id=str(user.id), message=f"boom for {user.id}"))
        await s.commit()
    return info


MODELS_DELETED = [
    Evidence,
    Recording,
    Device,
    Alert,
    NetworkActivity,
    AppScan,
    WifiScan,
    AiConversation,
    AppInstallEvent,
    BehaviorEvent,
    CloneReport,
    CommunityScamReport,
    EmergencyContact,
    ElderlyConfig,
    LinkScan,
    ScamCall,
    SecurityReport,
    FamilyMember,
    WarriorApplication,
    WarriorProfile,
]


async def _count(session_factory, model, where=None):
    from sqlalchemy import func

    async with session_factory() as s:
        q = select(func.count()).select_from(model)
        if where is not None:
            q = q.where(where)
        return (await s.execute(q)).scalar_one()


async def _delete(client, headers):
    return await client.request(
        "DELETE", ME, headers=headers, json=await delete_body(headers)
    )


async def test_full_erasure_deletes_everything_user_linked_and_keeps_only_policy_records(
    client, session_factory, make_user, auth_headers, _upload_dirs
):
    victim = await make_user("victim", phone="+919811111111")
    bystander = await make_user("bystander", phone="+919822222222")
    vh, bh = auth_headers(victim), auth_headers(bystander)
    info = await _populate(session_factory, client, vh, victim, _upload_dirs)
    # bystander owns a recording + evidence + files that must survive
    other = await _populate(session_factory, client, bh, bystander, _upload_dirs)

    r = await _delete(client, vh)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "permanently" not in body["message"].lower()  # no false claim
    assert body["retained"] and any("audit" in x for x in body["retained"])
    assert body["user_id"] == str(victim.id)

    # --- identity removed, tombstone kept
    async with session_factory() as s:
        row = (await s.execute(select(User).where(User.id == victim.id))).scalar_one()
        assert row.is_active is False
        for col in (
            "email",
            "phone",
            "alt_phone",
            "first_name",
            "last_name",
            "full_name",
            "hashed_password",
            "flat_no",
            "building",
            "street",
            "city",
            "state",
            "pin_code",
            "country",
        ):
            assert getattr(row, col) is None, col

    # --- every user-linked table is empty for the victim
    for model in MODELS_DELETED:
        owner_col = getattr(model, "user_id", None)
        if model in (NetworkActivity, AppScan, WifiScan):
            continue  # linked via device; asserted by totals below
        assert await _count(session_factory, model, owner_col == victim.id) == 0, (
            model.__name__
        )
    # device-linked children: only the bystander's rows are left (1 each)
    for model in (NetworkActivity, AppScan, WifiScan):
        assert await _count(session_factory, model) == 1, model.__name__

    # --- Cyber Warrior removal
    assert (
        await _count(
            session_factory, WarriorProfile, WarriorProfile.user_id == victim.id
        )
        == 0
    )
    assert (
        await _count(
            session_factory, WarriorApplication, WarriorApplication.user_id == victim.id
        )
        == 0
    )

    # --- OTPs for the victim's e-mail/phone are gone; the bystander's remain
    assert await _count(session_factory, OTP, OTP.email == victim.email) == 0
    assert await _count(session_factory, OTP, OTP.phone == "+919811111111") == 0
    assert await _count(session_factory, OTP, OTP.email == bystander.email) == 1

    # --- physical files + share token
    assert all(not p.exists() for p in info["files"]), "victim files still on disk"
    assert (await client.get(info["share_url"])).status_code in (403, 404)
    assert all(p.exists() for p in other["files"]), "bystander files were deleted"
    assert (await client.get(other["share_url"])).status_code == 200

    # --- retained: audit trail; anonymised: error log; untouched: others
    assert (
        await _count(session_factory, WarriorAuditLog) == 2
    )  # victim's + bystander's both kept
    assert (
        await _count(session_factory, ErrorLog, ErrorLog.user_id == str(victim.id)) == 0
    )
    assert (
        await _count(
            session_factory, ErrorLog, ErrorLog.message == f"boom for {victim.id}"
        )
        == 1
    )
    assert (
        await _count(session_factory, ErrorLog, ErrorLog.user_id == str(bystander.id))
        == 1
    )

    # --- bystander still has all their rows
    for model in (
        Evidence,
        Recording,
        Device,
        EmergencyContact,
        ElderlyConfig,
        FamilyMember,
    ):
        assert (
            await _count(session_factory, model, model.user_id == bystander.id) == 1
        ), model.__name__


async def test_family_links_pointing_at_deleted_user_are_cleared_not_deleted(
    client, session_factory, make_user, auth_headers
):
    victim, owner = await make_user("v"), await make_user("o")
    async with session_factory() as s:
        s.add(make_row(FamilyMember, user_id=owner.id, member_user_id=victim.id))
        await s.commit()
    assert (await _delete(client, auth_headers(victim))).status_code == 200
    async with session_factory() as s:
        fm = (
            await s.execute(
                select(FamilyMember).where(FamilyMember.user_id == owner.id)
            )
        ).scalar_one()
        assert fm.member_user_id is None


async def test_repeated_deletion_and_post_deletion_access_are_denied(
    client, session_factory, make_user, auth_headers
):
    from app.routers.auth import create_tokens

    user = await make_user("gone")
    tokens = create_tokens(str(user.id), user.email)
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (await _delete(client, h)).status_code == 200
    # second deletion, /me and any protected route: 401
    assert (await _delete(client, h)).status_code == 401
    assert (await client.get(ME, headers=h)).status_code == 401
    assert (await client.get("/api/v1/evidence/", headers=h)).status_code == 401
    # the still-valid refresh token cannot resurrect the account
    r = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r.status_code == 401


async def test_same_email_can_register_again_as_a_new_account(
    client, session_factory, make_user, auth_headers, monkeypatch
):
    from types import SimpleNamespace

    async def _ok(identifier, code):
        return SimpleNamespace(success=True, error=None, method="email")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _ok)
    user = await make_user("again", email="again.person@example.com")
    assert (await _delete(client, auth_headers(user))).status_code == 200
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "first_name": "Again",
            "email": "again.person@example.com",
            "consent": {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"},
        },
    )
    assert r.status_code == 200, r.text


async def test_confirmation_is_still_required(client, make_user, auth_headers):
    user = await make_user("noconfirm")
    r = await client.request(
        "DELETE",
        ME,
        headers=auth_headers(user),
        json=await delete_body(auth_headers(user), confirm="yes"),
    )
    assert r.status_code == 422
    assert (await client.get(ME, headers=auth_headers(user))).status_code == 200


async def test_file_outside_upload_dirs_is_never_deleted(
    client, session_factory, make_user, auth_headers, tmp_path
):
    """A tampered/legacy DB path must not let erasure delete arbitrary files."""
    victim = await make_user("trav")
    outside = tmp_path.parent / f"outside_{uuid.uuid4().hex}.txt"
    outside.write_text("keep me")
    async with session_factory() as s:
        s.add(make_row(Evidence, user_id=victim.id, file_path=str(outside)))
        await s.commit()
    r = await _delete(client, auth_headers(victim))
    assert r.status_code == 200
    assert outside.exists(), "erasure deleted a file outside the upload directories"
    outside.unlink()
    async with session_factory() as s:
        assert (
            await s.execute(text("select count(*) from evidence"))
        ).scalar_one() == 0


async def test_erasure_is_atomic_if_a_table_delete_fails(
    client, session_factory, make_user, auth_headers, monkeypatch
):
    """A failure mid-way must roll back: data and files stay, account stays active, 500."""
    victim = await make_user("atomic")
    h = auth_headers(victim)
    up = await client.post(
        "/api/v1/evidence/upload",
        headers=h,
        data={"title": "ev"},
        files={"file": ("e.png", PNG, "image/png")},
    )
    assert up.status_code == 200
    import app.services.account_erasure as ae

    real = ae._del

    async def _boom(db, name, stmt, result):
        if name == "link_scans":
            raise RuntimeError("simulated DB failure")
        return await real(db, name, stmt, result)

    monkeypatch.setattr(ae, "_del", _boom)
    r = await client.request("DELETE", ME, headers=h, json=await delete_body(h))
    assert r.status_code == 500
    monkeypatch.setattr(ae, "_del", real)
    assert await _count(session_factory, Evidence, Evidence.user_id == victim.id) == 1
    assert (await client.get(ME, headers=h)).status_code == 200
