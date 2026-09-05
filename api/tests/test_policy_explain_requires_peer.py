import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_policy_explain_requires_peer(
    client: AsyncClient,
    demo_token: str,
):
    auth = {"Authorization": f"Bearer {demo_token}"}

    resp = await client.get("/api/v1/peers/my/policy-explain", headers=auth)
    assert resp.status_code == 404, resp.text
