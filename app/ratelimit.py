"""Per-process rate limiting for local development. Production requires a shared store."""
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request

from .config import settings

_lock = Lock()
_hits: dict[str, deque] = defaultdict(deque)


def limit_token_requests(request: Request) -> None:
    # Do not trust client-supplied X-Forwarded-For headers.
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _lock:
        q = _hits[ip]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= settings.rate_limit:
            raise HTTPException(429, "Too many token requests", headers={"Retry-After": "60"})
        q.append(now)
