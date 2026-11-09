"""Admin CRUD, analytics and resource-update regression tests."""
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import admin_auth
from app.main import app


def test_admin_create_update_analytics_and_roles(monkeypatch):
    key = "ci-admin-key-of-sufficient-length-123456789"
    monkeypatch.setattr(admin_auth, "settings", SimpleNamespace(
        admin_oidc_issuer="", admin_oidc_audience="", admin_oidc_jwks_url="",
        production=False, admin_key=key,
    ))
    with TestClient(app) as http:
        headers = {"X-Admin-Key": key}
        created = http.post("/admin/clients", headers=headers, json={
            "scopes": ["orders:read"], "default_scopes": ["orders:read"],
            "resources": ["orders-api", "reports-api"],
        })
        assert created.status_code == 201, created.text
        client_id = created.json()["client_id"]
        updated = http.put("/admin/clients/" + client_id, headers=headers, json={
            "scopes": ["orders:read"], "default_scopes": ["orders:read"],
            "resources": ["reports-api"], "active": True,
        })
        assert updated.status_code == 200, updated.text
        clients = http.get("/admin/clients", headers=headers)
        assert clients.status_code == 200
        assert next(c for c in clients.json() if c["client_id"] == client_id)["resources"] == ["reports-api"]
        response = http.get("/admin/analytics", headers=headers)
        assert response.status_code == 200, response.text
        assert "hourly" in response.json()
        assert http.get("/admin/analytics").status_code == 401
