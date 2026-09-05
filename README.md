# VPN-ZTNA

Zero Trust Network Access на базе WireGuard, FastAPI, PostgreSQL.

## Быстрый старт

Установите Docker и Docker Compose:
```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl enable docker --now
Клонируйте репозиторий:

bash
git clone <your-repo-url> /opt/vpnztna
cd /opt/vpnztna
Настройте переменные окружения (скопируйте пример и отредактируйте):

bash
cp .env.example .env.prod
# Укажите POSTGRES_PASSWORD и SECRET_KEY
Запустите production-сборку:

bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
Проверьте работу:

bash
curl http://localhost:8000/health
curl http://localhost:8000/ready
curl http://localhost:8000/metrics
API эндпоинты
GET /health – проверка работоспособности

GET /ready – проверка готовности (БД)

GET /metrics – метрики Prometheus

POST /api/v1/auth/login – получение JWT (OAuth2 form)

GET /api/v1/peers – список пиров (только admin)

Полная документация доступна по адресу http://localhost:8000/docs (Swagger UI).

Тестирование
bash
cd api
PYTHONPATH=. pytest -q
Структура проекта
api/ – бэкенд FastAPI (основное приложение)

wg-gateway/ – микросервис управления WireGuard

app_ui/ – шаблоны Jinja2 для интерфейса

docker-compose.prod.yml – конфигурация для production

Лицензия
MIT
