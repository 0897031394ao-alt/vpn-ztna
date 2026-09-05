import pytest
from httpx import AsyncClient


@pytest.mark.integration
@pytest.mark.anyio
async def test_logout_revokes_session(client: AsyncClient, seeded_db: dict):
    # Используем данные из seeded_db
    resp_login = await client.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": seeded_db["demo_pw"],
        },
    )
    assert resp_login.status_code == 200, resp_login.text

    tokens = resp_login.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Проверяем, что токен работает
    resp_me_before = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp_me_before.status_code == 200, resp_me_before.text

    # Логаут
    resp_logout = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
    )
    assert resp_logout.status_code == 200, resp_logout.text

    # После логаута refresh-токен не должен работать
    resp_refresh_after = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp_refresh_after.status_code == 401, resp_refresh_after.text
