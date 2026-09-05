# VPN-ZTNA Platform

**Self‑hosted Zero Trust Network Access (ZTNA) на базе WireGuard, FastAPI, PostgreSQL и HTMX.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![WireGuard](https://img.shields.io/badge/WireGuard-✔-orange.svg)](https://www.wireguard.com/)

---

## �� О проекте

VPN-ZTNA — это полностью self‑hosted платформа Zero Trust Network Access, которая сочетает в себе:

- **WireGuard** — быстрый и безопасный VPN-протокол.
- **Динамические политики доступа** — разрешайте или запрещайте доступ к ресурсам на основе пользователей, групп и условий.
- **Автоматическое provisioning** — при создании политики автоматически создаётся и настраивается WireGuard-пир для всех затронутых пользователей.
- **Удобный веб‑интерфейс** — администрирование через современный HTMX-интерфейс с модальными окнами, пагинацией и фильтрацией.
- **Полная наблюдаемость** — встроенные метрики Prometheus, аудит логов, health‑checks.

Проект разработан как open‑source альтернатива коммерческим решениям (Tailscale, Twingate, Cloudflare Access) с полным контролем над данными и инфраструктурой.

---

## �� Быстрый старт

### Требования

- **Docker** и **Docker Compose** (установлены)
- **Linux** (рекомендуется Ubuntu 22.04/24.04)

### 1. Клонируйте репозиторий
