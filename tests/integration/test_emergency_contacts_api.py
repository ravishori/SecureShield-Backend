"""Emergency contacts: validation, partial update semantics, ownership isolation."""

import uuid

import pytest

pytestmark = pytest.mark.integration

URL = "/api/v1/emergency-contacts"


async def _create(client, headers, **body):
    r = await client.post(URL, headers=headers, json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def test_create_list_and_delete_roundtrip(client, make_user, auth_headers):
    u = await make_user("ec")
    h = auth_headers(u)
    c = await _create(client, h, name="  Asha Rao ", relationship="Sister", phone="+91 98765-43210", email="asha@example.com")
    assert c["name"] == "Asha Rao" and c["phone"] == "+91 98765-43210" and c["user_id"] == str(u.id)
    assert [x["id"] for x in (await client.get(URL, headers=h)).json()] == [c["id"]]
    d = await client.delete(f"{URL}/{c['id']}", headers=h)
    assert d.status_code == 200 and d.json()["id"] == c["id"]
    assert (await client.get(URL, headers=h)).json() == []


@pytest.mark.parametrize("body", [
    {"name": "X"},                                              # no phone/email: undeliverable
    {"name": "X", "phone": "", "email": ""},
    {"name": "", "phone": "123456"},
    {"name": "   ", "phone": "123456"},
    {"name": "X", "phone": "abcdef"},
    {"name": "X", "phone": "12"},
    {"name": "X", "email": "not-an-email"},
    {"name": "N" * 151, "phone": "123456"},
    {"name": "X", "phone": "123456", "relationship": "r" * 101},
    {"name": "X", "phone": "1" * 31},
    {},
])
async def test_invalid_contacts_are_422_not_500(client, make_user, auth_headers, body):
    u = await make_user("bad")
    assert (await client.post(URL, headers=auth_headers(u), json=body)).status_code == 422


async def test_phone_only_and_email_only_contacts_are_valid(client, make_user, auth_headers):
    h = auth_headers(await make_user("ok"))
    assert (await _create(client, h, name="P", phone="9876543210"))["email"] is None
    assert (await _create(client, h, name="E", email="e@example.com"))["phone"] is None


async def test_partial_update_changes_only_supplied_fields(client, make_user, auth_headers):
    h = auth_headers(await make_user("upd"))
    c = await _create(client, h, name="Ravi", relationship="Brother", phone="9876543210", email="r@example.com")
    r = await client.patch(f"{URL}/{c['id']}", headers=h, json={"relationship": "Cousin"})
    assert r.status_code == 200
    j = r.json()
    assert (j["name"], j["relationship"], j["phone"], j["email"]) == ("Ravi", "Cousin", "9876543210", "r@example.com")


async def test_empty_string_clears_a_field_but_not_the_last_channel(client, make_user, auth_headers):
    h = auth_headers(await make_user("clr"))
    c = await _create(client, h, name="Meera", phone="9876543210", email="m@example.com")
    assert (await client.patch(f"{URL}/{c['id']}", headers=h, json={"phone": ""})).json()["phone"] is None
    last = await client.patch(f"{URL}/{c['id']}", headers=h, json={"email": ""})
    assert last.status_code == 400 and "phone or email" in last.json()["detail"].lower()
    # the contact is unchanged after the rejected update
    again = (await client.get(URL, headers=h)).json()[0]
    assert again["email"] == "m@example.com"


@pytest.mark.parametrize("patch", [{"phone": "abc"}, {"email": "nope"}, {"name": "N" * 151}, {"phone": "1" * 31}])
async def test_invalid_update_values_are_422(client, make_user, auth_headers, patch):
    h = auth_headers(await make_user("pv"))
    c = await _create(client, h, name="Z", phone="9876543210")
    assert (await client.patch(f"{URL}/{c['id']}", headers=h, json=patch)).status_code == 422


async def test_blank_name_update_is_rejected(client, make_user, auth_headers):
    h = auth_headers(await make_user("nm"))
    c = await _create(client, h, name="Z", phone="9876543210")
    r = await client.patch(f"{URL}/{c['id']}", headers=h, json={"name": ""})
    assert r.status_code == 400


async def test_users_cannot_see_change_or_delete_each_others_contacts(client, make_user, auth_headers):
    owner, other = await make_user("own"), await make_user("oth")
    c = await _create(client, auth_headers(owner), name="Secret Contact", phone="9876543210")
    ho = auth_headers(other)
    assert (await client.get(URL, headers=ho)).json() == []
    assert (await client.patch(f"{URL}/{c['id']}", headers=ho, json={"name": "Hacked"})).status_code == 404
    assert (await client.delete(f"{URL}/{c['id']}", headers=ho)).status_code == 404
    assert (await client.get(URL, headers=auth_headers(owner))).json()[0]["name"] == "Secret Contact"


async def test_invalid_and_unknown_ids(client, make_user, auth_headers):
    h = auth_headers(await make_user("ids"))
    assert (await client.patch(f"{URL}/not-a-uuid", headers=h, json={"name": "x"})).status_code == 400
    assert (await client.delete(f"{URL}/not-a-uuid", headers=h)).status_code == 400
    assert (await client.patch(f"{URL}/{uuid.uuid4()}", headers=h, json={"name": "x"})).status_code == 404
    assert (await client.delete(f"{URL}/{uuid.uuid4()}", headers=h)).status_code == 404


async def test_requires_authentication(client):
    assert (await client.get(URL)).status_code in (401, 403)
    assert (await client.post(URL, json={"name": "x", "phone": "123456"})).status_code in (401, 403)
    assert (await client.patch(f"{URL}/{uuid.uuid4()}", json={"name": "x"})).status_code in (401, 403)
