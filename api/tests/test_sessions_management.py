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
async def test_list_sessions_returns_current_and_other_sessions(
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
    assert login_2["access_token"]

    resp_sessions = await asyncclient.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_sessions.status_code == 200, resp_sessions.text

    data = resp_sessions.json()
    assert "items" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) >= 2

    items = data["items"]
    current_items = [item for item in items if item.get("is_current") is True]
    other_items = [item for item in items if item.get("is_current") is False]

    assert len(current_items) == 1
    assert len(other_items) >= 1

    current_session = current_items[0]
    assert current_session["session_uuid"]
    assert current_session["is_revoked"] is False

    for item in items:
        assert "session_uuid" in item
        assert item["session_uuid"]
        assert "is_current" in item
        assert "is_revoked" in item


@pytest.mark.integration
@pytest.mark.anyio
async def test_delete_specific_session_revokes_that_session(
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

    resp_sessions_before = await asyncclient.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_sessions_before.status_code == 200, resp_sessions_before.text
    items_before = resp_sessions_before.json()["items"]

    target_sessions = [item for item in items_before if item.get("is_current") is False]
    assert len(target_sessions) >= 1
    target_session_uuid = target_sessions[0]["session_uuid"]

    resp_delete = await asyncclient.delete(
        f"/api/v1/auth/sessions/{target_session_uuid}",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_delete.status_code in (200, 204), resp_delete.text

    resp_current_deleted_session = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_2}"},
    )
    assert resp_current_deleted_session.status_code in (401, 403, 404), resp_current_deleted_session.text

    resp_current_active_session = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_current_active_session.status_code == 200, resp_current_active_session.text

    resp_sessions_after = await asyncclient.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_sessions_after.status_code == 200, resp_sessions_after.text
    items_after = resp_sessions_after.json()["items"]

    revoked_target = [item for item in items_after if item["session_uuid"] == target_session_uuid]
    assert len(revoked_target) == 1
    assert revoked_target[0]["is_revoked"] is True


@pytest.mark.integration
@pytest.mark.anyio
async def test_delete_other_sessions_leaves_only_current_active(
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

    login_3 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access_3 = login_3["access_token"]

    resp_sessions_before = await asyncclient.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_sessions_before.status_code == 200, resp_sessions_before.text
    items_before = resp_sessions_before.json()["items"]
    assert len(items_before) >= 3

    resp_revoke_others = await asyncclient.delete(
        "/api/v1/auth/sessions/others",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_revoke_others.status_code in (200, 204), resp_revoke_others.text

    resp_current_1 = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_current_1.status_code == 200, resp_current_1.text

    resp_current_2 = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_2}"},
    )
    assert resp_current_2.status_code in (401, 403, 404), resp_current_2.text

    resp_current_3 = await asyncclient.get(
        "/api/v1/auth/sessions/current",
        headers={"Authorization": f"Bearer {access_3}"},
    )
    assert resp_current_3.status_code in (401, 403, 404), resp_current_3.text

    resp_sessions_after = await asyncclient.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {access_1}"},
    )
    assert resp_sessions_after.status_code == 200, resp_sessions_after.text
    items_after = resp_sessions_after.json()["items"]

    current_items = [item for item in items_after if item.get("is_current") is True]
    active_items = [item for item in items_after if item.get("is_revoked") is False]

    assert len(current_items) == 1
    assert len(active_items) == 1
    assert active_items[0]["is_current"] is True


@pytest.mark.integration
@pytest.mark.anyio
async def test_delete_unknown_session_returns_404(
    asyncclient: AsyncClient,
    seeded_db: dict,
):
    login_data = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access = login_data["access_token"]

    resp_delete = await asyncclient.delete(
        "/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp_delete.status_code == 404, resp_delete.text
