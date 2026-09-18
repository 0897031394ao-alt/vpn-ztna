from uuid import UUID

import pytest
from sqlalchemy import select

from app.models.auth_session import AuthSession
from app.models.user import User


pytestmark = pytest.mark.asyncio


async def _login(asyncclient, username: str, password: str) -> dict:
    r = await asyncclient.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    return data


async def _auth_get(asyncclient, path: str, token: str):
    return await asyncclient.get(
        path,
        headers={"Authorization": f"Bearer {token}"},
    )


async def _auth_post(asyncclient, path: str, token: str, json: dict | None = None):
    return await asyncclient.post(
        path,
        headers={"Authorization": f"Bearer {token}"},
        json=json or {},
    )


async def _auth_delete(asyncclient, path: str, token: str):
    return await asyncclient.delete(
        path,
        headers={"Authorization": f"Bearer {token}"},
    )


async def test_ui_user_toggle_routes_are_unique():
    from app.main import app

    targets = {
        "/ui/users/{user_id}/toggle-active": (
            "app.api.ui_admin_fragments.ui_user_toggle_active"
        ),
        "/ui/users/{user_id}/toggle-admin": (
            "app.api.ui_admin_fragments.ui_user_toggle_admin"
        ),
    }

    found = {path: [] for path in targets}

    def join_path(prefix: str, path: str) -> str:
        prefix = prefix or ""
        path = path or ""

        if not prefix:
            return path or "/"

        if not path or path == "/":
            return prefix or "/"

        return prefix.rstrip("/") + "/" + path.lstrip("/")

    def visit(routes, prefix: str = ""):
        for route in routes:
            included = getattr(route, "original_router", None)

            if included is not None:
                context = getattr(route, "include_context", None)
                nested_prefix = getattr(context, "prefix", "") or ""

                visit(
                    getattr(included, "routes", []),
                    join_path(prefix, nested_prefix),
                )
                continue

            path = getattr(route, "path", None)
            methods = set(getattr(route, "methods", set()) or set())

            if not path:
                continue

            full_path = join_path(prefix, path)

            if full_path not in targets:
                continue

            endpoint = getattr(route, "endpoint", None)
            label = (
                f"{getattr(endpoint, '__module__', '?')}."
                f"{getattr(endpoint, '__name__', '?')}"
            )

            found[full_path].append(
                {
                    "methods": methods,
                    "label": label,
                    "dependencies": len(
                        getattr(route, "dependencies", []) or []
                    ),
                }
            )

    visit(app.routes)

    for path, expected_handler in targets.items():
        entries = found[path]

        assert len(entries) == 1, (path, entries)

        entry = entries[0]

        assert "POST" in entry["methods"], entry
        assert entry["label"] == expected_handler, entry
        assert entry["dependencies"] >= 1, entry


async def test_login_creates_session_and_me_returns_current_user(
    asyncclient,
    seeded_db,
    db_session_factory,
):
    login = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    access_token = login["access_token"]

    me = await _auth_get(asyncclient, "/api/v1/auth/me", access_token)
    assert me.status_code == 200, me.text

    body = me.json()
    assert body["username"] == seeded_db["demo"]["username"]
    assert body["email"] == seeded_db["demo"]["email"]
    assert body["is_admin"] is False

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuthSession).where(AuthSession.user_id == seeded_db["demo"]["id"])
        )
        sessions = result.scalars().all()

    assert len(sessions) >= 1

    current = sessions[-1]
    assert current.user_id == seeded_db["demo"]["id"]
    assert current.is_revoked is False
    assert current.session_uuid is not None
    UUID(str(current.session_uuid))


async def test_sessions_endpoint_returns_active_sessions(
    asyncclient,
    seeded_db,
):
    login1 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    login2 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )

    token1 = login1["access_token"]
    token2 = login2["access_token"]

    r1 = await _auth_get(asyncclient, "/api/v1/auth/sessions", token1)
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert "items" in body1
    assert len(body1["items"]) >= 2

    uuids = []
    for item in body1["items"]:
        assert "session_uuid" in item
        assert "is_revoked" in item
        assert item["is_revoked"] is False
        UUID(str(item["session_uuid"]))
        uuids.append(str(item["session_uuid"]))

    r2 = await _auth_get(asyncclient, "/api/v1/auth/sessions", token2)
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert len(body2["items"]) >= 2

    returned = {str(item["session_uuid"]) for item in body2["items"]}
    assert set(uuids).issubset(returned) or returned.issubset(set(uuids))


async def test_revoke_other_sessions_keeps_current_session_alive(
    asyncclient,
    seeded_db,
    db_session_factory,
):
    login1 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    login2 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )

    token1 = login1["access_token"]
    token2 = login2["access_token"]

    before = await _auth_get(asyncclient, "/api/v1/auth/sessions", token1)
    assert before.status_code == 200, before.text
    before_items = before.json()["items"]
    assert len(before_items) >= 2

    revoke = await _auth_delete(
        asyncclient,
        "/api/v1/auth/sessions/others",
        token1,
    )
    assert revoke.status_code in (200, 204), revoke.text

    me1 = await _auth_get(asyncclient, "/api/v1/auth/me", token1)
    assert me1.status_code == 200, me1.text

    me2 = await _auth_get(asyncclient, "/api/v1/auth/me", token2)
    assert me2.status_code == 401, me2.text

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuthSession).where(AuthSession.user_id == seeded_db["demo"]["id"])
        )
        sessions = result.scalars().all()

    active_count = sum(1 for s in sessions if not s.is_revoked)
    revoked_count = sum(1 for s in sessions if s.is_revoked)

    assert active_count == 1
    assert revoked_count >= 1


async def test_revoke_single_session_revokes_target_session(
    asyncclient,
    seeded_db,
):
    login1 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    login2 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )

    token1 = login1["access_token"]
    token2 = login2["access_token"]

    sessions_resp = await _auth_get(asyncclient, "/api/v1/auth/sessions", token1)
    assert sessions_resp.status_code == 200, sessions_resp.text
    items = sessions_resp.json()["items"]
    assert len(items) >= 2

    other = None
    for item in items:
        if not item.get("is_current", False):
            other = item
            break

    assert other is not None, items
    target_sid = other["session_uuid"]

    revoke = await _auth_delete(
        asyncclient,
        f"/api/v1/auth/sessions/{target_sid}",
        token1,
    )
    assert revoke.status_code in (200, 204), revoke.text

    me1 = await _auth_get(asyncclient, "/api/v1/auth/me", token1)
    assert me1.status_code == 200, me1.text

    me2 = await _auth_get(asyncclient, "/api/v1/auth/me", token2)
    assert me2.status_code == 401, me2.text


async def test_password_change_bumps_token_version_and_revokes_all_sessions(
    asyncclient,
    seeded_db,
    admin_token,
    db_session_factory,
):
    async with db_session_factory() as db:
        demo_user = await db.get(User, seeded_db["demo"]["id"])
        old_token_version = demo_user.token_version

    login1 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )
    login2 = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        seeded_db["demo_pw"],
    )

    token1 = login1["access_token"]
    token2 = login2["access_token"]

    change = await asyncclient.post(
        f"/ui/users/{seeded_db['demo']['id']}/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "new_password": "MyDemoPass456!",
            "confirm_password": "MyDemoPass456!",
        },
    )
    assert change.status_code == 200, change.text

    async with db_session_factory() as db:
        demo_user = await db.get(User, seeded_db["demo"]["id"])
        assert demo_user.token_version == old_token_version + 1

        result = await db.execute(
            select(AuthSession).where(AuthSession.user_id == demo_user.id)
        )
        sessions = result.scalars().all()

    assert len(sessions) >= 2
    assert all(s.is_revoked is True for s in sessions)

    me1 = await _auth_get(asyncclient, "/api/v1/auth/me", token1)
    me2 = await _auth_get(asyncclient, "/api/v1/auth/me", token2)
    assert me1.status_code == 401, me1.text
    assert me2.status_code == 401, me2.text

    relogin = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        "MyDemoPass456!",
    )
    me3 = await _auth_get(asyncclient, "/api/v1/auth/me", relogin["access_token"])
    assert me3.status_code == 200, me3.text


async def test_old_password_fails_after_password_change(
    asyncclient,
    seeded_db,
    admin_token,
):
    change = await asyncclient.post(
        f"/ui/users/{seeded_db['demo']['id']}/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "new_password": "MyDemoPass789!",
            "confirm_password": "MyDemoPass789!",
        },
    )
    assert change.status_code == 200, change.text

    old_login = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": seeded_db["demo_pw"],
        },
    )
    assert old_login.status_code in (400, 401), old_login.text

    new_login = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": "MyDemoPass789!",
        },
    )
    assert new_login.status_code == 200, new_login.text


async def test_refresh_token_reuse_revokes_session(
    asyncclient,
    seeded_db,
    admin_token,
    db_session_factory,
):
    new_password = "MyDemoPass901!"

    change = await asyncclient.post(
        f"/ui/users/{seeded_db['demo']['id']}/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert change.status_code == 200, change.text

    login = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        new_password,
    )

    access_token = login["access_token"]
    original_refresh = login["refresh_token"]

    current_resp = await _auth_get(
        asyncclient,
        "/api/v1/auth/sessions/current",
        access_token,
    )
    assert current_resp.status_code == 200, current_resp.text
    current_body = current_resp.json()
    session_uuid = current_body["session_uuid"]

    refresh1 = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
    )
    assert refresh1.status_code == 200, refresh1.text
    refresh1_body = refresh1.json()
    assert "access_token" in refresh1_body
    assert "refresh_token" in refresh1_body
    assert refresh1_body["refresh_token"] != original_refresh

    reuse = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
    )
    assert reuse.status_code == 401, reuse.text

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuthSession).where(AuthSession.session_uuid == session_uuid)
        )
        auth_session = result.scalar_one_or_none()

    assert auth_session is not None
    assert auth_session.is_revoked is True

    me_after_reuse = await _auth_get(
        asyncclient,
        "/api/v1/auth/me",
        refresh1_body["access_token"],
    )
    assert me_after_reuse.status_code == 401, me_after_reuse.text


async def test_logout_refresh_token_cannot_be_used_again(
    asyncclient,
    seeded_db,
    admin_token,
    db_session_factory,
):
    new_password = "MyDemoPass902!"

    change = await asyncclient.post(
        f"/ui/users/{seeded_db['demo']['id']}/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert change.status_code == 200, change.text

    login = await _login(
        asyncclient,
        seeded_db["demo"]["username"],
        new_password,
    )

    access_token = login["access_token"]
    refresh_token = login["refresh_token"]

    current_resp = await _auth_get(
        asyncclient,
        "/api/v1/auth/sessions/current",
        access_token,
    )
    assert current_resp.status_code == 200, current_resp.text
    session_uuid = current_resp.json()["session_uuid"]

    logout = await asyncclient.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
    )
    assert logout.status_code == 200, logout.text

    refresh_after_logout = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_after_logout.status_code == 401, refresh_after_logout.text

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuthSession).where(AuthSession.session_uuid == session_uuid)
        )
        auth_session = result.scalar_one_or_none()

    assert auth_session is not None
    assert auth_session.is_revoked is True
    assert auth_session.revoked_at is not None
