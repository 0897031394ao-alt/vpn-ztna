from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "vpnztna-api"

    DATABASE_URL: str = "postgresql+asyncpg://vpnztna:changeme@postgres:5432/vpnztna"
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    WG_AGENT_BASE_URL: str = "http://127.0.0.1:9000"
    WG_AGENT_TOKEN: str = "wg-agent-secret-2026"
    WG_AGENT_TIMEOUT: float = 5.0

    WG_SERVER_PUBLIC_KEY: str = "CHANGE_ME_SERVER_PUB"
    WG_SERVER_ENDPOINT: str = "vpn.example.com:51820"
    WG_CLIENT_DNS: str = "1.1.1.1"

    DISABLE_RATELIMIT: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
