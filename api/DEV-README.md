# VPNZTNA API — DEV README

Этот файл описывает, как в dev‑окружении поднимать backend, работать с БД и гонять интеграционные тесты.

## Стек

- Python 3.12
- FastAPI + Uvicorn
- PostgreSQL (asyncpg)
- SQLAlchemy (async)
- Alembic (миграции)
- pytest + anyio (async‑тесты)

## Структура репозитория

Корень `/opt/vpnztna`:

- `api/` — backend (этот каталог)
- `app_ui/` — Web UI
- `docker-compose.yml` — инфраструктура (PostgreSQL и другие сервисы)
- `scripts/` — вспомогательные скрипты
- `vpnztna_cli.py` — CLI
- `wg0.conf`, `wg-gateway` — WireGuard / VPN‑конфигурация

Каталог `/opt/vpnztna/api`:

- `app/` — код приложения
- `alembic/`, `alembic.ini` — миграции БД
- `pyproject.toml` — конфиг pytest и зависимостей
- `requirements.txt` — Python‑зависимости
- `tests/` — интеграционные тесты API
- `wg0.conf` — dev WireGuard конфиг

## Быстрый старт

### 1. Поднять инфраструктуру (PostgreSQL и т.п.)

Из корня репозитория:

```bash
cd /opt/vpnztna
docker-compose up -d
```

Порт и креды БД смотри в `docker-compose.yml`.

### 2. Виртуальное окружение

В корне (один venv на весь проект):

```bash
cd /opt/vpnztna

python3.12 -m venv .venv
source .venv/bin/activate

pip install -r api/requirements.txt
```

> Важно: venv лежит в `/opt/vpnztna/.venv`, а не в `api/.venv`.[file:50]

### 3. Переменные окружения

Минимально нужно задать `DATABASE_URL`. Пример:

```bash
export DATABASE_URL="postgresql+asyncpg://user:password@localhost:5432/vpnztna"
```

Для тестов используются дефолтные креды админа, но их можно переопределить:

```bash
export TEST_ADMIN_USERNAME="rootadmin"
export TEST_ADMIN_PASSWORD="Admin123!ZTNA"
```

Если env не заданы, helper `login_rootadmin` использует `rootadmin` / `Admin123!ZTNA` по умолчанию.[file:50]

### 4. Миграции

Из каталога `api`:

```bash
cd /opt/vpnztna/api
alembic upgrade head
```

Это создаст/обновит структуру БД и, если миграции так устроены, создаст базовых пользователей (admin, rootadmin, demo‑vpn‑user и т.п.).[file:50]

### 5. Запуск приложения

```bash
cd /opt/vpnztna/api
source /opt/vpnztna/.venv/bin/activate

PYTHONPATH=. uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API будет доступен по адресу: `http://127.0.0.1:8000`.

Если порт уже занят (`Address already in use`), значит сервер уже запущен в другом процессе.[file:50]

## Smoke‑проверки

### Health

```bash
curl -i -sS http://127.0.0.1:8000/health
```

Ожидаемый ответ:

```http
HTTP/1.1 200 OK
...
content-type: application/json

{"status":"ok","version":"0.1.0"}
```

[На реальном запуске ты уже видел именно такой ответ.][file:50]

### UI / Users

Проверка HTML‑таблицы пользователей:

```bash
curl -i -sS http://127.0.0.1:8000/ui/users/table | sed -n '1,40p'
```

Ожидается:

- статус `200 OK`;
- HTML с контейнером:

```html
<div id="users-table-wrapper">
  ...
  <h2 class="text-base font-semibold text-slate-100">Users</h2>
  ...
  <table ...> ... список пользователей ...
</div>
```

[Это подтверждает, что UI жив, HTMX‑таблица рендерится и в БД есть базовые пользователи.][file:50]

## Тесты

### Как устроены тесты

Все тесты в `tests/` — async‑интеграционные, работают in‑process:

- используется `httpx.AsyncClient` + `ASGITransport(app=app)`, то есть отдельный HTTP‑сервер не поднимается.[file:50]
- БД — реальный PostgreSQL, подключение через `SQLAlchemy` и `asyncpg`.

В `app/db/session.py` engine создаётся так:

```python
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    poolclass=NullPool,
)
```

`poolclass=NullPool` отключает пул соединений и предотвращает ошибки вида  
`Task ... got Future attached to a different loop` при pytest + anyio.[file:50]

### Запуск тестов

Из каталога `api`:

```bash
cd /opt/vpnztna/api
source /opt/vpnztna/.venv/bin/activate
```

Все тесты:

```bash
PYTHONPATH=. python -m pytest tests -ra
```

Один тест:

```bash
PYTHONPATH=. python -m pytest tests/test_user_policy_flow.py -ra
```

Если не активируешь venv, можно явно указать интерпретатор:

```bash
PYTHONPATH=. /opt/vpnztna/.venv/bin/python -m pytest tests -ra
```

> Важно: путь именно `/opt/vpnztna/.venv/bin/python`, а не `.venv/bin/python` из каталога `api`.[file:50]

### Что делает `tests/conftest.py`

Файл `tests/conftest.py` содержит общие фикстуры и helper’ы:

- `async_client` — `AsyncClient` c:

  ```python
  ASGITransport(app=app),
  base_url="http://test",
  follow_redirects=True,
  ```

  Используется во всех тестах.[file:50]

- `db_session` — async‑фикстура `AsyncSession`, основанная на `app.core.deps.get_db()`, то есть тот же session, что использует приложение.[file:50]

Helper‑функции:

- `auth_headers(token: str) -> dict[str, str]` — возвращает `{"Authorization": f"Bearer {token}"}`.[file:50]
- `login(async_client, username, password) -> str` — общий helper логина через `/api/v1/auth/login` с form‑данными `username` / `password`.[file:50]
- `login_demo_user(async_client) -> str` — логин тестового пользователя `demo-vpn-user` с паролем `MyDemoPass123!`.[file:50]
- `login_rootadmin(async_client) -> str` — логин админ‑пользователя:
  - username из `TEST_ADMIN_USERNAME` или `rootadmin`;
  - password из `TEST_ADMIN_PASSWORD` или `Admin123!ZTNA`.[file:50]
- `ensure_peer_enrolled(async_client, token) -> dict` — helper для self‑service enroll текущего peer:

  ```python
  resp = await async_client.post(
      "/api/v1/peers/my/enroll",
      headers=auth_headers(token),
  )
  assert resp.status_code in (200, 201)
  return resp.json()
  ```

  (Если требуется, можно использовать в тестах для быстрой подготовки peer.)

### Существующие интеграционные тесты

Сейчас покрыто 4 основных сценария:

- `tests/test_policy_explain_requires_peer.py`  
  Проверяет, что если у пользователя нет provisioned peer, то  
  `GET /api/v1/peers/my/policy-explain` возвращает `404` и правильный `detail`.[file:50]

- `tests/test_user_policy_flow.py`  
  Сценарий для `demo-vpn-user`:
  - логин;
  - `GET /api/v1/peers/my`;
  - `POST /api/v1/peers/my/enroll`;
  - `GET /api/v1/peers/my/policy-explain`;
  - проверки структуры ответа и ожидаемых CIDR’ов / `split_tunnel`.[file:50]

- `tests/test_peer_flow.py`  
  Полный peer‑flow:
  - логин demo‑пользователя;
  - enroll peer;
  - `my/config`, `my/policy-explain`;
  - логин админа и пересчёт peer;
  - admin‑policy‑explain для конкретного peer;
  - удаление peer;
  - проверка статуса peer и audit‑логов через БД.[file:50]

- `tests/test_admin_resource_policy_flow.py`  
  Сценарий для админа:
  - логин rootadmin;
  - создание ресурса (CIDR) через `/api/v1/resources`;
  - создание policy для demo‑пользователя через `/api/v1/policies`;
  - логин `demo-vpn-user`, enroll peer;
  - `policy-explain` и проверка, что новый CIDR попал в итоговый список.[file:50]

Новые интеграционные тесты рекомендуется писать по тому же шаблону:
- использовать `async_client`;
- логин только через `login_demo_user` / `login_rootadmin`;
- заголовки — через `auth_headers(token)`.

## Режим «быстрой проверки после изменений»

После любой нетривиальной правки удобно прогонять:

1. Один ключевой тест:

   ```bash
   PYTHONPATH=. python -m pytest tests/test_user_policy_flow.py -ra
   ```

2. Весь набор:

   ```bash
   PYTHONPATH=. python -m pytest tests -ra
   ```

3. Smoke UI:

   ```bash
   curl -sS http://127.0.0.1:8000/ui/users/table | sed -n '1,30p'
   ```

Если все три шага зелёные и HTML таблицы рендерятся, dev‑контур в порядке.[file:50]
