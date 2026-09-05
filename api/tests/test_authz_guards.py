import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_regular_user_cannot_create_resource(client: AsyncClient, demo_token: str):
    resp = await client.post(
        "/api/v1/resources/",
        json={"name": "hack", "cidr": "10.9.9.0/24"},
        headers={"Authorization": f"Bearer {demo_token}"},
    )
    assert resp.status_code == 403


async def test_regular_user_cannot_create_policy(client: AsyncClient, demo_token: str):
    resp = await client.post(
        "/api/v1/policies/",
        json={"user_id": 999, "resource_id": 999},
        headers={"Authorization": f"Bearer {demo_token}"},
    )
    assert resp.status_code == 403


async def test_regular_user_cannot_create_peer(client: AsyncClient, demo_token: str):
    resp = await client.post(
        "/api/v1/peers/",
        json={"name": "evil-peer"},
        headers={"Authorization": f"Bearer {demo_token}"},
    )
    assert resp.status_code == 403


async def test_regular_user_cannot_list_users(client: AsyncClient, demo_token: str):
    resp = await client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {demo_token}"},
    )
    assert resp.status_code == 403


async def test_unauthenticated_cannot_access_api(client: AsyncClient):
    resp = await client.get("/api/v1/peers/", follow_redirects=False)
    assert resp.status_code == 401


async def test_admin_can_list_resources(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/resources/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200


async def test_admin_can_list_users(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
