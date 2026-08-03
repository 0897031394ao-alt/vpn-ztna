FROM python:3.12-slim

RUN groupadd -g 112 apiuser && useradd -u 109 -g 112 -m apiuser

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        sudo \
        wireguard-tools \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install . \
    "python-jose[cryptography]" \
    "passlib[bcrypt]==1.7.4" \
    "bcrypt==4.0.1" \
    "email-validator" \
    "python-multipart" \
    "jinja2>=3.1.0" \
    "ua-parser==1.0.2" \
    "user-agents==2.2.0" \
    "qrcode[pil]"

COPY app ./app
COPY app_ui ./app_ui

USER apiuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
