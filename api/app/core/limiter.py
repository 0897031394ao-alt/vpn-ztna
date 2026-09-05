from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


if settings.DISABLE_RATELIMIT:
    limiter = Limiter(
        key_func=lambda *args, **kwargs: "test",
        enabled=False,
    )
else:
    limiter = Limiter(key_func=get_remote_address)
