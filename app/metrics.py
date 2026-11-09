import hmac

from fastapi import APIRouter, Header, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from starlette.responses import Response

from .config import settings

router = APIRouter()
token_requests = Counter("oauth_token_requests_total", "Token endpoint outcomes", ["outcome"])
admin_actions = Counter("oauth_admin_actions_total", "Admin actions", ["action"])


@router.get("/internal/metrics", include_in_schema=False)
def metrics(x_metrics_key: str | None = Header(default=None)):
    if not settings.metrics_key or not x_metrics_key or not hmac.compare_digest(x_metrics_key, settings.metrics_key):
        raise HTTPException(404, "Not found")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
