"""Community scam news feed: aggregation, corroboration threshold, city filter safety."""

import pytest

from app.models.community_scam import CommunityScamReport, ScamType

pytestmark = pytest.mark.integration

URL = "/api/v1/community-scams/news-feed"


async def add(session_factory, user, phone=None, city="Pune", n=1, url=None, active=True):
    async with session_factory() as s:
        for i in range(n):
            s.add(
                CommunityScamReport(
                    user_id=user.id, scam_type=ScamType.phishing_link, title=f"t{i}", description="d",
                    phone_number=phone, url=url, city=city, is_active=active,
                )
            )
        await s.commit()


async def test_requires_auth(client):
    assert (await client.get(URL)).status_code in (401, 403)


async def test_empty_community_still_returns_editorial_items(client, make_user, auth_headers):
    r = await client.get(URL, headers=auth_headers(await make_user("nf")))
    assert r.status_code == 200
    j = r.json()
    assert j["total_reports_this_week"] == 0 and j["items"] and all(i["source"] == "editorial" for i in j["items"])
    assert all(i["sample_phones"] == [] for i in j["items"])


async def test_aggregates_counts_severity_and_top_city(client, make_user, auth_headers, session_factory):
    u = await make_user("agg")
    await add(session_factory, u, n=3, city="Pune")
    await add(session_factory, u, n=1, city="Delhi")
    await add(session_factory, u, n=5, city="Pune", active=False)  # inactive ignored
    j = (await client.get(URL, headers=auth_headers(u))).json()
    com = [i for i in j["items"] if i["source"] == "community"]
    assert com[0]["reports_in_period"] == 4 and com[0]["severity"] == "warning"
    assert j["top_city"] == "Pune" and j["total_reports_this_week"] == 4


@pytest.mark.security
async def test_single_unverified_report_never_publishes_a_number(client, make_user, auth_headers, session_factory):
    u = await make_user("one")
    await add(session_factory, u, phone="+919800000001", url="http://evil.example/a")
    await add(session_factory, u, phone="+919800000002", n=2, url="http://evil.example/b")
    com = [i for i in (await client.get(URL, headers=auth_headers(u))).json()["items"] if i["source"] == "community"][0]
    assert com["sample_phones"] == ["+919800000002"] and com["sample_urls"] == ["http://evil.example/b"]


@pytest.mark.security
async def test_city_filter_treats_wildcards_literally_and_is_bounded(client, make_user, auth_headers, session_factory):
    u = await make_user("city")
    await add(session_factory, u, city="Pune")
    h = auth_headers(u)
    j = (await client.get(URL, params={"city": "%"}, headers=h)).json()
    assert j["total_reports_this_week"] == 0
    j = (await client.get(URL, params={"city": "pun"}, headers=h)).json()
    assert j["total_reports_this_week"] == 1
    assert (await client.get(URL, params={"city": "x" * 81}, headers=h)).status_code == 422
