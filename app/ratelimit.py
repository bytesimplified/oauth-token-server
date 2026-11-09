"""Redis atomic fixed-window limiter; development-only in-memory fallback."""
import time
from collections import defaultdict, deque
from threading import Lock

import redis
from fastapi import HTTPException, Request

from .config import settings

_lock = Lock()
_hits: dict[str, deque] = defaultdict(deque)
_redis = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1) if settings.redis_url else None


def limit_token_requests(request: Request) -> None:
    # Use direct socket peer, not spoofable X-Forwarded-For.
    ip = request.client.host if request.client else "unknown"
    now = int(time.time())
    if _redis:
        key = f"oauth:rate:{ip}:{now // 60}"
        try:
            count = _redis.eval(
                "local count = redis.call('INCR', KEYS[1]); "
                "if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end; "
                "return count",
                1, key, 120,
            )
        except redis.RedisError:
            # Fail closed when the configured production limiter is unavailable.
            raise HTTPException(503, "Rate limiter unavailable") from None
        if count > settings.rate_limit:
            raise HTTPException(429, "Too many token requests", headers={"Retry-After": "60"})
        return

    if settings.production:
        raise HTTPException(503, "Rate limiter not configured")
    moment = time.monotonic()
    with _lock:
        q = _hits[ip]
        while q and q[0] <= moment - 60:
            q.popleft()
        if len(q) >= settings.rate_limit:
            raise HTTPException(429, "Too many token requests", headers={"Retry-After": "60"})
        q.append(moment)
