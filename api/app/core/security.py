from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise ValueError("Password must be at most 72 bytes for bcrypt")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    if len(password_bytes) > 72:
        return False
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(
    subject: str,
    token_version: int,
    expires_minutes: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = _utcnow()
    exp = now + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": "access",
        "ver": int(token_version),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(
    subject: str,
    token_version: int,
    session_id: str,
    refresh_jti: str | None = None,
    expires_days: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str]:
    now = _utcnow()
    exp = now + timedelta(
        days=expires_days or settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    jti = refresh_jti or str(uuid4())

    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": "refresh",
        "ver": int(token_version),
        "sid": str(session_id),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, jti


def decode_access_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        return None

    if payload.get("type") != "access":
        return None

    if payload.get("sub") is None:
        return None

    if payload.get("ver") is None:
        return None

    if not payload.get("sid"):
        return None

    return payload


def decode_refresh_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        return None

    if payload.get("type") != "refresh":
        return None

    if payload.get("sub") is None:
        return None

    if payload.get("ver") is None:
        return None

    if not payload.get("sid"):
        return None

    if not payload.get("jti"):
        return None

    return payload
