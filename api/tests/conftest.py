from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

# -------------------------------------------------------------------
# Environment override: use SQLite for tests
# -------------------------------------------------------------------
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
os.environ["TEST_DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.base import Base
from app.main import app
from app.models import (
    AuditEvent,
    AuthSession,
    Group,
    Peer,
    Policy,
    Resource,
    User,
    user_group,
)
from app.core.security import hash_password
from app.db.session import get_db


TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "sqlite+aiosqlite:///./test.db",
)


def _make_engine(url: str) -> AsyncEngine:
    connect_args: dict[str, Any] = {}
    engine_kwargs: dict[str, Any] = {
        "future": True,
        "pool_pre_ping": True,
    }

    if url.startswith("sqlite+aiosqlite"):
        connect_args["check_same_thread"] = False
    else:
        engine_kwargs["pool_size"] = 5
        engine_kwargs["max_overflow"] = 10

    return create_async_engine(
        url,
        connect_args=connect_args,
        **engine_kwargs,
    )


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def test_engine() -> AsyncIterator[AsyncEngine]:
    engine = _make_engine(TEST_DATABASE_URL)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def session_factory(
    test_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


@pytest_asyncio.fixture(scope="function", autouse=True)
async def prepare_test_db(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        await session.execute(delete(user_group))
        await session.execute(delete(Policy))
        await session.execute(delete(AuthSession))
        await session.execute(delete(AuditEvent))
        await session.execute(delete(Peer))
        await session.execute(delete(Resource))
        await session.execute(delete(Group))
        await session.execute(delete(User))
        await session.commit()

    yield

    async with session_factory() as session:
        await session.execute(delete(user_group))
        await session.execute(delete(Policy))
        await session.execute(delete(AuthSession))
        await session.execute(delete(AuditEvent))
        await session.execute(delete(Peer))
        await session.execute(delete(Resource))
        await session.execute(delete(Group))
        await session.execute(delete(User))
        await session.commit()


@pytest_asyncio.fixture(scope="function")
async def db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
def db_session_factory(
    session_factory: async_sessionmaker[AsyncSession],
):
    @asynccontextmanager
    async def _factory() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    return _factory


@pytest_asyncio.fixture(scope="function", autouse=True)
async def override_get_db(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async def _get_test_db() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def disable_rate_limiter() -> AsyncIterator[None]:
    limiter = getattr(app.state, "limiter", None)
    previous_enabled = getattr(limiter, "enabled", None) if limiter is not None else None

    if limiter is not None and hasattr(limiter, "enabled"):
        limiter.enabled = False

    yield

    if limiter is not None and hasattr(limiter, "enabled") and previous_enabled is not None:
        limiter.enabled = previous_enabled


# --- Основная фикстура HTTP-клиента (используется в тестах как asyncclient) ---
@pytest_asyncio.fixture(scope="function")
async def asyncclient() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"X-Forwarded-For": "127.0.0.1"},
        follow_redirects=True,
    ) as client:
        yield client


# --- Алиас для тестов, которые используют фикстуру client ---
@pytest_asyncio.fixture(scope="function")
async def client(asyncclient: AsyncClient) -> AsyncIterator[AsyncClient]:
    yield asyncclient


@pytest_asyncio.fixture(scope="function")
async def seeded_db(
    session_factory: async_sessionmaker[AsyncSession],
) -> dict[str, Any]:
    admin_password = "Admin1!"
    demo_password = "MyDemoPass123!"

    async with session_factory() as session:
        admin = User(
            username="admin",
            email="admin@vpnztna.dev",
            hashed_password=hash_password(admin_password),
            is_active=True,
            is_admin=True,
            token_version=1,
        )
        demo = User(
            username="demo-vpn-user",
            email="demo@vpnztna.dev",
            hashed_password=hash_password(demo_password),
            is_active=True,
            is_admin=False,
            token_version=1,
        )

        group = Group(
            name="demo-group",
            description="Demo group for tests",
        )

        # ИСПРАВЛЕНИЕ: resource_type должен быть 'host', 'cidr' или 'service'
        # Используем 'host' вместо 'server'
        resource = Resource(
            name="demo-resource",
            address="10.10.10.10",
            resource_type="host",  # было 'server'
            is_active=True,
        )

        session.add_all([admin, demo, group, resource])
        await session.flush()

        await session.execute(
            user_group.insert().values(user_id=demo.id, group_id=group.id)
        )

        await session.commit()

        return {
            "admin": {
                "id": admin.id,
                "username": admin.username,
                "email": admin.email,
                "is_admin": admin.is_admin,
            },
            "admin_pw": admin_password,
            "demo": {
                "id": demo.id,
                "username": demo.username,
                "email": demo.email,
                "is_admin": demo.is_admin,
            },
            "demo_pw": demo_password,
            "group": {
                "id": group.id,
                "name": group.name,
            },
            "resource": {
                "id": resource.id,
                "name": resource.name,
            },
        }


@pytest_asyncio.fixture(scope="function")
async def admin_token(asyncclient: AsyncClient, seeded_db: dict[str, Any]) -> str:
    resp = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["admin"]["username"],
            "password": seeded_db["admin_pw"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest_asyncio.fixture(scope="function")
async def demo_token(asyncclient: AsyncClient, seeded_db: dict[str, Any]) -> str:
    resp = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": seeded_db["demo_pw"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest_asyncio.fixture(scope="function")
async def demo_login(asyncclient: AsyncClient, seeded_db: dict[str, Any]) -> dict[str, Any]:
    resp = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["demo"]["username"],
            "password": seeded_db["demo_pw"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest_asyncio.fixture(scope="function")
async def admin_login(asyncclient: AsyncClient, seeded_db: dict[str, Any]) -> dict[str, Any]:
    resp = await asyncclient.post(
        "/api/v1/auth/login",
        data={
            "username": seeded_db["admin"]["username"],
            "password": seeded_db["admin_pw"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest_asyncio.fixture(scope="function")
async def fresh_demo_user(
    session_factory: async_sessionmaker[AsyncSession],
) -> dict[str, Any]:
    password = "FreshDemoPass123!"

    async with session_factory() as session:
        user = User(
            username="fresh-demo-user",
            email="fresh-demo@vpnztna.dev",
            hashed_password=hash_password(password),
            is_active=True,
            is_admin=False,
            token_version=1,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "password": password,
        }


@pytest_asyncio.fixture(scope="function")
async def auth_sessions(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[AuthSession]:
    async with session_factory() as session:
        result = await session.execute(
            select(AuthSession).order_by(AuthSession.created_at.asc())
        )
        return list(result.scalars().all())
