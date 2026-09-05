from httpx import AsyncClient

_token_cache: dict[str, str] = {}
_user_id_cache: dict[str, int] = {}


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def login(async_client: AsyncClient, username: str, password: str) -> str:
    cache_key = f"{username}:{password}"
    cached = _token_cache.get(cache_key)
    if cached:
        return cached

    resp = await async_client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200, resp.text

    token = resp.json()["access_token"]
    _token_cache[cache_key] = token
    return token


async def login_demo_user(async_client: AsyncClient) -> str:
    return await login(async_client, "demo-vpn-user", "MyDemoPass123!")


async def login_rootadmin(
    async_client: AsyncClient,
    username: str = "rootadmin",
    password: str = "Admin123!ZTNA",
) -> str:
    return await login(async_client, username, password)


async def get_demo_user_id(async_client: AsyncClient, admin_token: str | None = None) -> int:
    cached = _user_id_cache.get("demo-vpn-user")
    if cached is not None:
        return cached

    token = admin_token or await login_rootadmin(async_client)
    resp = await async_client.get(
        "/api/v1/users",
        headers=auth_headers(token),
    )
    assert resp.status_code == 200, resp.text

    data = resp.json()
    users = data if isinstance(data, list) else data.get("items", data)

    for user in users:
        if user.get("username") == "demo-vpn-user":
            user_id = user["id"]
            _user_id_cache["demo-vpn-user"] = user_id
            return user_id

    raise AssertionError("demo-vpn-user not found in /api/v1/users response")
