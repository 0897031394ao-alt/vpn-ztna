# VPNZTNA API — DEV README

Этот файл описывает, как локально поднимать backend, работать с БД и гонять тесты.

## Стек

- Python 3.12
- FastAPI + Uvicorn
- PostgreSQL (asyncpg)
- SQLAlchemy (async)
- Alembic (миграции)
- pytest + anyio (async-тесты)

## Структура

Репозиторий `/opt/vpnztna`:

- `api/` — backend (этот каталог)
- `app_ui/` — Web UI
- `docker-compose.yml` — инфраструктура (DB, сервисы)
- `scripts/` — вспомогательные скрипты
- `vpnztna_cli.py` — CLI

Каталог `api/`:

- `app/` — код приложения
- `alembic/`, `alembic.ini` — миграции БД
- `pyproject.toml` — настройки pytest и зависимостей
- `requirements.txt` — зависимости
- `tests/` — интеграционные тесты API

## Быстрый старт для разработки

### 1. Поднять инфраструктуру через docker-compose (если нужно)

Из корня репозитория:

```bash
cd /opt/vpnztna
docker-compose up -d
```

Обычно это поднимает PostgreSQL и вспомогательные сервисы (смотри `docker-compose.yml` для деталей).

### 2. Установить зависимости и venv

Внутри `api/`:

```bash
cd /opt/vpnztna/api

python3.12 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Настроить переменные окружения

Минимально нужно указать URL БД в `app/core/config.py` / переменных окружения:

- `DATABASE_URL` — например:

```bash
export DATABASE_URL="postgresql+asyncpg://user:password@localhost:5432/vpnztna"
```

Для тестов используются дефолтные креды админа, но их можно переопределить:

```bash
export TEST_ADMIN_USERNAME="rootadmin"
export TEST_ADMIN_PASSWORD="Admin123!ZTNA"
```

### 4. Прогнать миграции

Из каталога `api/`:

```bash
alembic upgrade head
```

После этого структура БД должна быть создана, и встроенные пользователи/данные (если они создаются миграциями/скриптами) будут доступны.

### 5. Запуск приложения

Локальный запуск через Uvicorn:

```bash
PYTHONPATH=. uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

После этого API будет доступен по адресу `http://127.0.0.1:8000`.

## Тесты

### Общие принципы

- Все тесты сейчас async и используют `httpx.AsyncClient` + `ASGITransport`, то есть приложение гоняется **in-process**, без реального HTTP-сервера.[file:50]
- БД — реальная PostgreSQL, к ней подключается `SQLAlchemy` через `create_async_engine` с `asyncpg` и `NullPool` (это важно для корректной работы async‑тестов).[file:50]
- Основные интеграционные тесты лежат в `tests/`:
  - `test_policy_explain_requires_peer.py`
  - `test_user_policy_flow.py`
  - `test_peer_flow.py`
  - `test_admin_resource_policy_flow.py`[file:50]

### Запуск всех тестов

Из каталога `api/`:

```bash
PYTHONPATH=. .venv/bin/python -m pytest tests -ra
```

### Как устроен тестовый клиент и логин

В `tests/conftest.py` определены:

- `async_client` — фикстура `AsyncClient` с `ASGITransport(app=app)`, базовый URL `http://test`, `follow_redirects=True`.[file:50]
- `db_session` — async‑фикстура, использующая `app.core.deps.get_db()`, то есть тот же `AsyncSession`, что и само приложение.[file:50]
- `auth_headers(token)` — helper для `Authorization: Bearer <token>`.[file:50]
- `login(async_client, username, password)` — общий helper логина через `/api/v1/auth/login`.[file:50]
- `login_demo_user(async_client)` — логин пользователя `demo-vpn-user` с тестовым паролем `MyDemoPass123!`.[file:50]
- `login_rootadmin(async_client)` — логин админа `rootadmin` с паролем `Admin123!ZTNA` (либо из `TEST_ADMIN_USERNAME/TEST_ADMIN_PASSWORD`).[file:50]
- `ensure_peer_enrolled(async_client, token)` — helper для self‑service enroll текущего peer пользователя.[file:50]

Новые интеграционные тесты стоит писать по тому же шаблону:
- всегда использовать `async_client` фикстуру;
- логин — только через `login_demo_user` / `login_rootadmin` или обёртки над ними;
- заголовки авторизации — через `auth_headers()`.

### Как добавить новый интеграционный тест

1. Создать новый файл в `tests/`, например `tests/test_some_feature.py`.
2. Использовать такой шаблон:

```python
import pytest
from httpx import AsyncClient

from tests.conftest import auth_headers, login_rootadmin


@pytest.mark.integration
@pytest.mark.anyio
async def test_some_feature(async_client: AsyncClient):
    token = await login_rootadmin(async_client)
    headers = auth_headers(token)

    resp = await async_client.get(
        "/api/v1/some-endpoint",
        headers=headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    # проверки структуры/данных
```

3. Запустить:

```bash
PYTHONPATH=. .venv/bin/python -m pytest tests/test_some_feature.py -ra
```

## Особенности БД для тестов

В `app/db/session.py` engine настроен так:

- используется `create_async_engine(settings.DATABASE_URL, pool_pre_ping=True, poolclass=NullPool)` — это отключает пул соединений и предотвращает ошибки вида `Task ... attached to a different loop` при async‑тестах на anyio.[file:50]

Если ты меняешь конфиг engine или переходишь на другой способ управления пулом, помни, что для pytest с anyio это важно.

---

Дальше DEV‑README можно дополнять:

- описанием smoke‑сценариев;
- списком тестовых пользователей;
- образом данных, который ожидается в БД после миграций/инициализации.
