import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_demo_user_sees_only_allowed_resources(
    client: AsyncClient,
    admin_token: str,
    demo_token: str,
    seeded_db: dict,
):
    admin_h = {"Authorization": f"Bearer {admin_token}"}
    demo_h = {"Authorization": f"Bearer {demo_token}"}
    demo_id = seeded_db["demo"]["id"]

    r1 = await client.post(
        "/api/v1/resources/",
        json={"name": "res-A", "resource_type": "cidr", "address": "10.1.0.0/24"},
        headers=admin_h,
    )
    r2 = await client.post(
        "/api/v1/resources/",
        json={"name": "res-B", "resource_type": "cidr", "address": "10.2.0.0/24"},
        headers=admin_h,
    )
    assert r1.status_code in (200, 201), r1.text
    assert r2.status_code in (200, 201), r2.text

    res_a_id = r1.json()["id"]
    res_b_id = r2.json()["id"]

    rp = await client.post(
        "/api/v1/policies/",
        json={"name": "demo-allow-res-a", "user_id": demo_id, "resource_id": res_a_id},
        headers=admin_h,
    )
    assert rp.status_code in (200, 201), rp.text

    rc = await client.get(
        f"/api/v1/access/check?user_id={demo_id}&resource_id={res_a_id}",
        headers=demo_h,
    )
    assert rc.status_code == 200, rc.text
    body = rc.json()
    assert body["allowed"] is True
    assert body["decision"] == "allow"

    rc2 = await client.get(
        f"/api/v1/access/check?user_id={demo_id}&resource_id={res_b_id}",
        headers=demo_h,
    )
    assert rc2.status_code == 200, rc2.text
    body2 = rc2.json()
    assert body2["allowed"] is False
    assert body2["decision"] == "deny"
