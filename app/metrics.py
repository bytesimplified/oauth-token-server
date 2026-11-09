"""Low-cardinality service metrics; protected from public scraping."""
import hmac
import time

from fastapi import APIRouter, Header, HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

from .config import settings

router = APIRouter()
token_requests = Counter("oauth_token_requests_total", "Token endpoint outcomes", ["outcome"])
admin_actions = Counter("oauth_admin_actions_total", "Admin actions", ["action"])
http_requests = Counter("oauth_http_requests_total", "HTTP requests", ["route", "method", "status"])
http_duration = Histogram(
    "oauth_http_duration_seconds", "HTTP request latency", ["route", "method"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)


async def observe_request(request: Request, call_next):
    start = time.monotonic()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        matched = request.scope.get("route")
        route = getattr(matched, "path", "unmatched")
        http_requests.labels(route, request.method, str(status)).inc()
        http_duration.labels(route, request.method).observe(time.monotonic() - start)


@router.get("/internal/metrics", include_in_schema=False)
def metrics(x_metrics_key: str | None = Header(default=None)):
    if not settings.metrics_key or not x_metrics_key or not hmac.compare_digest(x_metrics_key, settings.metrics_key):
        raise HTTPException(404, "Not found")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
