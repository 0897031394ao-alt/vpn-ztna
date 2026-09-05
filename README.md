VPN-ZTNA Platform
Self‑hosted Zero Trust Network Access (ZTNA) на базе WireGuard, FastAPI, PostgreSQL и HTMX.

https://img.shields.io/badge/License-AGPL%2520v3-blue.svg
https://img.shields.io/badge/python-3.12-blue.svg
https://img.shields.io/badge/FastAPI-0.115-green.svg
https://img.shields.io/badge/WireGuard-%E2%9C%94-orange.svg

О проекте
VPN-ZTNA — полностью self‑hosted платформа Zero Trust Network Access, которая сочетает:

WireGuard — быстрый и безопасный VPN-протокол.

Динамические политики доступа — доступ к ресурсам на основе пользователей, групп и условий.

Автоматическое provisioning — при создании политики автоматически создаётся и настраивается WireGuard-пир для всех затронутых пользователей.

Удобный веб‑интерфейс — администрирование через HTMX-интерфейс с модальными окнами, пагинацией и фильтрацией.

Полная наблюдаемость — встроенные метрики Prometheus, аудит логов, health‑checks.

Проект разработан как open‑source альтернатива коммерческим решениям (Tailscale, Twingate, Cloudflare Access) с полным контролем над данными и инфраструктурой.

Быстрый старт
Требования
Docker и Docker Compose

Linux (рекомендуется Ubuntu 22.04/24.04)

1. Клонируйте репозиторий
bash
git clone https://github.com/0897031394ao-alt/vpn-ztna.git /opt/vpnztna
cd /opt/vpnztna
2. Настройте переменные окружения
bash
cp .env.example .env.prod
nano .env.prod
Обязательно задайте:

SECRET_KEY — сгенерируйте случайную строку (например, openssl rand -hex 32).

POSTGRES_PASSWORD — надёжный пароль для базы данных.

3. Запустите систему
bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
4. Проверьте работу
bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.1.0"}
Откройте в браузере http://ваш-сервер:8000/login.
Учётные данные по умолчанию:

Логин: admin

Пароль: Admin_2026_Strong!

⚠️ Обязательно смените пароль после первого входа!

Архитектура
Компонент	Назначение
API (FastAPI)	Управление пользователями, пирами, политиками, ресурсами, группами. REST API и веб‑интерфейс.
WireGuard Gateway	Управляет WireGuard-интерфейсом (wg set, wg syncconf). Принимает команды от API.
PostgreSQL	Хранилище данных: пользователей, пиров, политик, ресурсов, групп, сессий, аудита.
Фоновый воркер (provision-worker) обрабатывает пиры со статусом pending и применяет их в WireGuard.

Администрирование
Веб-интерфейс
После входа доступны разделы:

Users — управление пользователями (активация, роли, группы).

Groups — создание групп и привязка пользователей.

Resources — добавление защищаемых ресурсов (CIDR, host, service).

Policies — создание правил доступа (user/group → resource, allow/deny).

Debug Access / Check / Peer — инструменты для проверки работы Policy Engine.

Все таблицы поддерживают пагинацию, фильтры и HTMX-обновления (без перезагрузки страницы).

API (Swagger)
Интерактивная документация: http://localhost:8000/docs

Основные эндпоинты:

Метод	Путь	Описание
POST	/api/v1/auth/login	Получение JWT
POST	/api/v1/auth/refresh	Обновление токена
POST	/api/v1/auth/logout	Завершение сессии
GET	/api/v1/peers	Список пиров (admin)
POST	/api/v1/policies	Создание политики (admin)
GET	/api/v1/audit	Логи аудита
Разработка и тестирование
Локальный запуск (без Docker)
bash
cd /opt/vpnztna/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
Запуск тестов
bash
cd /opt/vpnztna/api
PYTHONPATH=. pytest -q
Метрики и мониторинг
Метрики Prometheus доступны по адресу: http://localhost:8000/metrics

Вклад в проект
Форкните репозиторий.

Создайте ветку: git checkout -b feature/amazing-feature.

Закоммитьте изменения: git commit -m 'Add amazing feature'.

Запушьте: git push origin feature/amazing-feature.

Откройте Pull Request.

Лицензия
GNU Affero General Public License v3.0.
Подробнее: https://www.gnu.org/licenses/agpl-3.0.html

Благодарности
WireGuard

FastAPI

HTMX

TailwindCSS

Контакты
Создайте Issue в GitHub или свяжитесь через личные сообщения.

Сделано с ❤️ для безопасного и контролируемого удалённого доступа.
