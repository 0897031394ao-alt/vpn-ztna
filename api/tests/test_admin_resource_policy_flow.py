import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_admin_can_add_resource_and_policy_for_demo_user(
    client: AsyncClient,
    admin_token: str,
    seeded_db: dict,
):
    auth = {"Authorization": f"Bearer {admin_token}"}
    demo_user_id = seeded_db["demo"]["id"]

    r1 = await client.post(
        "/api/v1/resources/",
        json={
            "name": "internal-svc",
            "resource_type": "cidr",
            "address": "10.10.0.0/24",
        },
        headers=auth,
    )
    assert r1.status_code in (200, 201), r1.text
    resource_id = r1.json()["id"]

    r2 = await client.post(
        "/api/v1/policies/",
        json={
            "name": "demo-access-internal-svc",
            "user_id": demo_user_id,
            "resource_id": resource_id,
        },
        headers=auth,
    )
    assert r2.status_code in (200, 201), r2.text
    policy = r2.json()

    assert policy["user_id"] == demo_user_id
    assert policy["resource_id"] == resource_id
