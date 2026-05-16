import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.peer import Peer
from app.models.audit_log import AuditLog


@pytest.mark.anyio
async def test_full_peer_flow(async_client: AsyncClient, db_session: AsyncSession):
    # 1. Берём существующего пользователя testuser
    user = (
        await db_session.execute(
            select(User).where(User.username == "testuser")
        )
    ).scalar_one()

    # 2. Логинимся как user
    resp = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    token_user = resp.json()["access_token"]
    auth_user = {"Authorization": f"Bearer {token_user}"}

    # 3. enroll-peer для user
    resp = await async_client.post(
        f"/api/v1/peers/users/{user.id}/enroll-peer",
        headers=auth_user,
    )
    assert resp.status_code == 200
    body = resp.json()
    peer_id = body["peer_id"]

    # Проверяем, что peer создан в БД
    peer = await db_session.get(Peer, peer_id)
    assert peer is not None
    assert peer.user_id == user.id

    # 4. my/config
    resp = await async_client.get("/api/v1/peers/my/config", headers=auth_user)
    assert resp.status_code == 200
    assert "wg0.conf" in resp.headers.get("Content-Disposition", "")

    # 5. my/policy-explain
    resp = await async_client.get("/api/v1/peers/my/policy-explain", headers=auth_user)
    assert resp.status_code == 200
    explain = resp.json()
    assert explain["peer_id"] == peer_id
    assert explain["user_id"] == user.id
    assert isinstance(explain["final_cidrs_before_aggregation"], list)

    # 6. Логинимся как admin
    resp = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "NewStrongPass123!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    token_admin = resp.json()["access_token"]
    auth_admin = {"Authorization": f"Bearer {token_admin}"}

    # 7. Ручной пересчёт
    resp = await async_client.post(
        f"/api/v1/peers/{peer_id}/recalculate", headers=auth_admin
    )
    assert resp.status_code == 200

    # 8. Админский policy-explain
    resp = await async_client.get(
        f"/api/v1/peers/{peer_id}/policy-explain", headers=auth_admin
    )
    assert resp.status_code == 200

    # 9. Удаляем peer как админ
    resp = await async_client.delete(
        f"/api/v1/peers/{peer_id}", headers=auth_admin
    )
    assert resp.status_code == 200
    await db_session.refresh(peer)
    assert peer.provisioning_status.name.lower() == "removed"

    # 10. Проверяем ключевые события в audit_logs
    result = await db_session.execute(
        select(AuditLog.action, AuditLog.user_id, AuditLog.peer_id)
        .where(AuditLog.peer_id == peer_id)
        .order_by(AuditLog.id)
    )
    actions = [row for row in result.all()]
    action_names = [a[0] for a in actions]

    for expected in [
        "peer_created",
        "peer_recalculated",
        "peer_provisioned",
        "peer.enroll",
        "peer.get_config",
        "peer.my_policy_explain",
        "peer.recalculate_manual",
        "peer.policy_explain",
        "peer_removed",
        "peer.remove",
    ]:
        assert expected in action_names




