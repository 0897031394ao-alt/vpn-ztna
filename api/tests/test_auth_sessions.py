import pytest
from httpx import AsyncClient


async def _login(asyncclient: AsyncClient, username: str, password: str) -> dict:
    resp = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": username,
            "password": password,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.integration
@pytest.mark.anyio
async def test_logout_with_invalid_refresh_token(
    asyncclient: AsyncClient,
    seeded_db: dict,
):
    login_data = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access = login_data["access_token"]
    refresh = login_data["refresh_token"]

    fake_refresh = refresh[:-2] + "xx"

    resp_logout = await asyncclient.post(
        "/api/v1/auth/logout",
        json={"refresh_token": fake_refresh},
        headers={"Authorization": f"Bearer {access}"},
    )

    assert resp_logout.status_code in (400, 401)


@pytest.mark.integration
@pytest.mark.anyio
async def test_refresh_after_logout_fails(
    asyncclient: AsyncClient,
    seeded_db: dict,
):
    login_data = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access = login_data["access_token"]
    refresh = login_data["refresh_token"]

    resp_logout = await asyncclient.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp_logout.status_code in (200, 204), resp_logout.text

    resp_refresh = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh},
    )
    assert resp_refresh.status_code in (401, 403), resp_refresh.text


@pytest.mark.integration
@pytest.mark.anyio
async def test_old_refresh_token_cannot_be_reused(
    asyncclient: AsyncClient,
    seeded_db: dict,
):
    login_data = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    old_refresh = login_data["refresh_token"]

    resp_refresh_1 = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert resp_refresh_1.status_code == 200, resp_refresh_1.text
    refresh_data_1 = resp_refresh_1.json()
    new_refresh = refresh_data_1["refresh_token"]

    assert new_refresh != old_refresh

    resp_refresh_2 = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert resp_refresh_2.status_code in (401, 403), resp_refresh_2.text


@pytest.mark.integration
@pytest.mark.anyio
async def test_revoke_other_sessions_invalidates_other_access_tokens(
    asyncclient: AsyncClient,
    seeded_db: dict,
):
    login_1 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access_1 = login_1["access_token"]

    login_2 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access_2 = login_2["access_token"]

    resp_current_1 = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_current_1.status_code == 200, resp_current_1.text

    resp_current_2 = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_2}"},
    )
    assert resp_current_2.status_code == 200, resp_current_2.text

    resp_revoke_others = await asyncclient.delete(
        "/api/v1/auth/sessions/others",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_revoke_others.status_code in (200, 204), resp_revoke_others.text

    resp_current_1_after = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_current_1_after.status_code == 200, resp_current_1_after.text

    resp_current_2_after = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_2}"},
    )
    assert resp_current_2_after.status_code in (401, 403, 404), resp_current_2_after.text


@pytest.mark.integration
@pytest.mark.anyio
async def test_current_session_endpoint_returns_session(
    asyncclient: AsyncClient,
    seeded_db: dict,
):
    login_data = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access = login_data["access_token"]

    resp_current = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access}"},
    )

    assert resp_current.status_code == 200, resp_current.text
    data = resp_current.json()

    assert "session_uuid" in data
    assert data["session_uuid"] is not None
    assert data["is_current"] is True
    assert "ip_address" in data
    assert "user_agent" in data
    assert data["is_revoked"] is False
