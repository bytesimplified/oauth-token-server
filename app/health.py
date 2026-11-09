"""Liveness and readiness: avoid exposing configuration or upstream endpoints."""
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import settings
from .crypto import public_key
from .db import engine
from .ratelimit import _redis

router = APIRouter(tags=["health"])


@router.get("/health/live", include_in_schema=False)
def live():
    return {"status": "ok"}


@router.get("/health/ready", include_in_schema=False)
def ready():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        if settings.redis_url and (_redis is None or not _redis.ping()):
            raise RuntimeError("Redis unavailable")
        public_key()
    except Exception:
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return {"status": "ready"}
