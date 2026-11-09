import os
import jwt
from fastapi.testclient import TestClient

from app.crypto import key_id, private_key
from app.main import app

# Test runner sets this before app import in conftest.
from app.config import settings

ADMIN_KEY = "test-admin-key-that-is-at-least-32-characters"


def test_admin_is_disabled_by_default():
    with TestClient(app) as http:
        response = http.get("/admin/clients")
        assert response.status_code == 503


def test_revocation_is_enforced():
    from app.cli import create_client
    from app.db import SessionLocal, RevokedToken, jti_hash
    client_id, secret = create_client(["orders:read"], ["orders:read"])
    with TestClient(app) as http:
        response = http.post("/oauth/token", auth=(client_id, secret),
                             data={"grant_type": "client_credentials"})
        assert response.status_code == 200
        token = response.json()["access_token"]
        claims = jwt.decode(token, options={"verify_signature": False})
        assert http.get("/api/orders", headers={"Authorization": "Bearer " + token}).status_code == 200
        from datetime import datetime, timezone
        with SessionLocal.begin() as db:
            db.add(RevokedToken(jti_hash=jti_hash(claims["jti"]),
                                expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc)))
        assert http.get("/api/orders", headers={"Authorization": "Bearer " + token}).status_code == 401
