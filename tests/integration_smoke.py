"""Real PostgreSQL + Redis integration test, run as a standalone script."""
import os

assert os.environ.get("OAUTH_DB_URL", "").startswith("postgresql+psycopg://")
assert os.environ.get("OAUTH_REDIS_URL", "").startswith("redis://")

import redis
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.config import settings
from app.db import engine
from app.main import app

assert "alembic_version" in inspect(engine).get_table_names(), "Migrations not applied"
with engine.connect() as db:
    version = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
assert version == "0002_resources", version
assert redis.from_url(settings.redis_url).ping()

with TestClient(app) as http:
    assert http.get("/health/ready").status_code == 200
    headers = {"X-Admin-Key": settings.admin_key}
    registration = http.post("/admin/clients", headers=headers, json={
        "scopes": ["orders:read"], "default_scopes": ["orders:read"],
        "resources": ["orders-api", "reports-api"],
    })
    assert registration.status_code == 201, registration.text
    client_id, secret = registration.json()["client_id"], registration.json()["client_secret"]

    token_result = http.post("/oauth/token", auth=(client_id, secret), data={
        "grant_type": "client_credentials", "resource": "reports-api",
    })
    assert token_result.status_code == 200, token_result.text
    token = token_result.json()["access_token"]
    assert jwt.decode(token, options={"verify_signature": False})["aud"] == "reports-api"
    assert http.post("/oauth/introspect", auth=(client_id, secret),
                     data={"token": token}).json()["active"] is True
    assert http.post("/oauth/revoke", auth=(client_id, secret),
                     data={"token": token}).status_code == 200
    assert http.post("/oauth/introspect", auth=(client_id, secret),
                     data={"token": token}).json()["active"] is False
    assert http.get("/admin/analytics", headers=headers).status_code == 200
    assert http.get("/internal/metrics", headers={"X-Metrics-Key": settings.metrics_key}).status_code == 200
    assert http.get("/internal/metrics").status_code == 404
    assert http.put("/admin/clients/" + client_id, headers=headers, json={
        "scopes": ["orders:read"], "default_scopes": ["orders:read"],
        "resources": ["orders-api"], "active": True,
    }).status_code == 200
    assert http.post("/oauth/token", auth=(client_id, secret), data={
        "grant_type": "client_credentials", "resource": "reports-api",
    }).json()["error"] == "invalid_target"

assert list(redis.from_url(settings.redis_url).scan_iter("oauth:rate:*"))
print("PostgreSQL migrations, Redis limiter, OAuth, analytics, metrics, audience and revocation: PASS")
