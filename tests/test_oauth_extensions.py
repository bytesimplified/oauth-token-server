import jwt
from fastapi.testclient import TestClient

from app.cli import create_client
from app.main import app


def test_introspection_and_standard_revocation():
    client_id, secret = create_client(["orders:read"], ["orders:read"])
    with TestClient(app) as http:
        token = http.post("/oauth/token", auth=(client_id, secret),
                          data={"grant_type": "client_credentials"}).json()["access_token"]
        result = http.post("/oauth/introspect", auth=(client_id, secret), data={"token": token})
        assert result.status_code == 200
        assert result.json()["active"] is True
        revoked = http.post("/oauth/revoke", auth=(client_id, secret), data={"token": token})
        assert revoked.status_code == 200
        result = http.post("/oauth/introspect", auth=(client_id, secret), data={"token": token})
        assert result.json() == {"active": False}
        assert http.get("/api/orders", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_resource_audience_restriction():
    client_id, secret = create_client(["orders:read"], ["orders:read"])
    with TestClient(app) as http:
        response = http.post("/oauth/token", auth=(client_id, secret),
                             data={"grant_type": "client_credentials", "resource": "unauthorized-api"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_target"
