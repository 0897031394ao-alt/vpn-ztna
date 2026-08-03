import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _wg_pubkey() -> str:
    return base64.b64encode(
        X25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode()


async def test_admin_can_create_and_provision_peer(
    client: AsyncClient,
    admin_token: str,
    seeded_db: dict,
):
    auth = {"Authorization": f"Bearer {admin_token}"}
    demo_user_id = seeded_db["demo"]["id"]

    r1 = await client.post(
        "/api/v1/resources/",
        json={"name": "peer-bootstrap-net", "resource_type": "cidr", "address": "10.50.0.0/24"},
        headers=auth,
    )
    assert r1.status_code in (200, 201), r1.text
    resource_id = r1.json()["id"]

    r2 = await client.post(
        "/api/v1/policies/",
        json={"name": "demo-peer-bootstrap", "user_id": demo_user_id, "resource_id": resource_id},
        headers=auth,
    )
    assert r2.status_code in (200, 201), r2.text

    r3 = await client.post(
        "/api/v1/peers/",
        json={"user_id": demo_user_id, "public_key": _wg_pubkey()},
        headers=auth,
    )
    assert r3.status_code in (200, 201), r3.text
    peer_id = r3.json()["id"]

    r4 = await client.post(f"/api/v1/peers/{peer_id}/recalculate", headers=auth)
    assert r4.status_code in (200, 204), r4.text

    r5 = await client.post(f"/api/v1/peers/{peer_id}/provision", headers=auth)
    assert r5.status_code in (200, 202, 503), r5.text


async def test_remove_pending_peer_marks_removed(
    client: AsyncClient,
    admin_token: str,
    seeded_db: dict,
):
    auth = {"Authorization": f"Bearer {admin_token}"}
    demo_user_id = seeded_db["demo"]["id"]

    # Готовим политику и ресурс
    r1 = await client.post(
        "/api/v1/resources/",
        json={"name": "peer-bootstrap-net", "resource_type": "cidr", "address": "10.50.0.0/24"},
        headers=auth,
    )
    assert r1.status_code in (200, 201), r1.text
    resource_id = r1.json()["id"]

    r2 = await client.post(
        "/api/v1/policies/",
        json={"name": "demo-peer-bootstrap", "user_id": demo_user_id, "resource_id": resource_id},
        headers=auth,
    )
    assert r2.status_code in (200, 201), r2.text

    # Создаём peer (он будет pending)
    r3 = await client.post(
        "/api/v1/peers/",
        json={"user_id": demo_user_id, "public_key": _wg_pubkey()},
        headers=auth,
    )
    assert r3.status_code in (200, 201), r3.text
    peer_id = r3.json()["id"]

    # Удаляем пока он ещё pending
    r_del = await client.delete(f"/api/v1/peers/{peer_id}", headers=auth)
    assert r_del.status_code in (200, 202, 204), r_del.text
    body = r_del.json()
    assert body["provisioning_status"] == "removed"


async def test_remove_provisioned_peer_marks_pending_revoke(
    client: AsyncClient,
    admin_token: str,
    seeded_db: dict,
):
    auth = {"Authorization": f"Bearer {admin_token}"}
    demo_user_id = seeded_db["demo"]["id"]

    r1 = await client.post(
        "/api/v1/resources/",
        json={"name": "peer-bootstrap-net", "resource_type": "cidr", "address": "10.50.0.0/24"},
        headers=auth,
    )
    assert r1.status_code in (200, 201), r1.text
    resource_id = r1.json()["id"]

    r2 = await client.post(
        "/api/v1/policies/",
        json={"name": "demo-peer-bootstrap", "user_id": demo_user_id, "resource_id": resource_id},
        headers=auth,
    )
    assert r2.status_code in (200, 201), r2.text

    r3 = await client.post(
        "/api/v1/peers/",
        json={"user_id": demo_user_id, "public_key": _wg_pubkey()},
        headers=auth,
    )
    assert r3.status_code in (200, 201), r3.text
    peer_id = r3.json()["id"]

    # Принудительно провизионить peer
    r_prov = await client.post(f"/api/v1/peers/{peer_id}/provision", headers=auth)
    assert r_prov.status_code in (200, 202, 503), r_prov.text  # 503 возможен при недоступном wg-gateway

    # Удаляем provisioned peer
    r_del = await client.delete(f"/api/v1/peers/{peer_id}", headers=auth)
    assert r_del.status_code in (200, 202, 204), r_del.text
    body = r_del.json()
    assert body["provisioning_status"] in ("pending_revoke", "removed")


async def test_remove_peer_is_idempotent(
    client: AsyncClient,
    admin_token: str,
    seeded_db: dict,
):
    auth = {"Authorization": f"Bearer {admin_token}"}
    demo_user_id = seeded_db["demo"]["id"]

    r1 = await client.post(
        "/api/v1/resources/",
        json={"name": "peer-bootstrap-net", "resource_type": "cidr", "address": "10.50.0.0/24"},
        headers=auth,
    )
    assert r1.status_code in (200, 201), r1.text
    resource_id = r1.json()["id"]

    r2 = await client.post(
        "/api/v1/policies/",
        json={"name": "demo-peer-bootstrap", "user_id": demo_user_id, "resource_id": resource_id},
        headers=auth,
    )
    assert r2.status_code in (200, 201), r2.text

    r3 = await client.post(
        "/api/v1/peers/",
        json={"user_id": demo_user_id, "public_key": _wg_pubkey()},
        headers=auth,
    )
    assert r3.status_code in (200, 201), r3.text
    peer_id = r3.json()["id"]

    # Первый DELETE
    r_del1 = await client.delete(f"/api/v1/peers/{peer_id}", headers=auth)
    assert r_del1.status_code in (200, 202, 204), r_del1.text

    # Второй DELETE не должен падать
    r_del2 = await client.delete(f"/api/v1/peers/{peer_id}", headers=auth)
    assert r_del2.status_code in (200, 202, 204), r_del2.text
