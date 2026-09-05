import pytest
from sqlalchemy import select

from app.models.audit_event import AuditEvent


pytestmark = pytest.mark.asyncio


async def _login(asyncclient, username: str, password: str) -> dict:
    r = await asyncclient.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _latest_events_for_user(session_factory, user_id: int, limit: int = 20):
    async with session_factory() as session:
        result = await session.execute(
            select(AuditEvent)
            .where(AuditEvent.user_id == user_id)
            .order_by(AuditEvent.id.desc())
            .limit(limit)
        )
        return result.scalars().all()


async def test_login_success_writes_audit_event(
    asyncclient,
    seeded_db,
    db_session_factory,
):
    login = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": seeded_db["demo_pw"],
        },
        headers={"User-Agent": "pytest-audit-login"},
    )
    assert login.status_code == 200, login.text

    events = await _latest_events_for_user(db_session_factory, seeded_db["demo"]["id"])
    assert events, "No audit events found for demo user"

    event = next((e for e in events if e.event_type == "login_success"), None)
    assert event is not None, [e.event_type for e in events]
    assert event.user_id == seeded_db["demo"]["id"]
    assert event.ip_address is not None
    assert event.user_agent == "pytest-audit-login"
    assert event.details["username"] == seeded_db["demo"]["username"]
    assert "session_id" in event.details

    details_text = str(event.details)
    assert seeded_db["demo_pw"] not in details_text
    assert "refresh_token" not in details_text
    assert "access_token" not in details_text


async def test_refresh_reuse_writes_audit_event(
    asyncclient,
    seeded_db,
    admin_token,
    db_session_factory,
):
    new_password = "MyDemoPass903!"

    change = await asyncclient.post(
        f"/ui/users/{seeded_db['demo']['id']}/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert change.status_code == 200, change.text

    login = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": new_password,
        },
        headers={"User-Agent": "pytest-audit-refresh"},
    )
    assert login.status_code == 200, login.text
    login_data = login.json()
    original_refresh = login_data["refresh_token"]

    refresh_ok = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
        headers={"User-Agent": "pytest-audit-refresh"},
    )
    assert refresh_ok.status_code == 200, refresh_ok.text

    reuse = await asyncclient.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
        headers={"User-Agent": "pytest-audit-refresh"},
    )
    assert reuse.status_code == 401, reuse.text

    events = await _latest_events_for_user(
        db_session_factory, seeded_db["demo"]["id"], limit=30
    )
    assert events, "No audit events found for demo user"

    reuse_event = next(
        (e for e in events if e.event_type == "refresh_token_reuse_detected"), None
    )
    assert reuse_event is not None, [e.event_type for e in events]
    assert reuse_event.user_id == seeded_db["demo"]["id"]
    assert reuse_event.user_agent == "pytest-audit-refresh"
    assert reuse_event.details["reason"] == "refresh_token_reuse"
    assert "session_id" in reuse_event.details
    assert "presented_jti" in reuse_event.details
    assert "expected_jti" in reuse_event.details

    details_text = str(reuse_event.details)
    assert original_refresh not in details_text
    assert new_password not in details_text
    assert "access_token" not in details_text


async def test_logout_writes_audit_event(
    asyncclient,
    seeded_db,
    admin_token,
    db_session_factory,
):
    new_password = "MyDemoPass904!"

    change = await asyncclient.post(
        f"/ui/users/{seeded_db['demo']['id']}/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert change.status_code == 200, change.text

    login = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": new_password,
        },
        headers={"User-Agent": "pytest-audit-logout"},
    )
    assert login.status_code == 200, login.text
    login_data = login.json()

    logout = await asyncclient.post(
        "/api/v1/auth/logout",
        json={"refresh_token": login_data["refresh_token"]},
        headers={"User-Agent": "pytest-audit-logout"},
    )
    assert logout.status_code == 200, logout.text

    events = await _latest_events_for_user(
        db_session_factory, seeded_db["demo"]["id"], limit=30
    )
    assert events, "No audit events found for demo user"

    logout_event = next(
        (e for e in events if e.event_type == "logout_success"), None
    )
    assert logout_event is not None, [e.event_type for e in events]
    assert logout_event.user_id == seeded_db["demo"]["id"]
    assert logout_event.user_agent == "pytest-audit-logout"
    assert "session_id" in logout_event.details

    details_text = str(logout_event.details)
    assert login_data["refresh_token"] not in details_text
    assert new_password not in details_text
    assert "access_token" not in details_text
