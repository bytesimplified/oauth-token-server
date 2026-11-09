from fastapi.testclient import TestClient
from app.cli import create_client, deactivate_client
from app.crypto import verify_access_token
from app.main import app

CLIENT_ID, SECRET = create_client(["orders:read", "orders:write"], ["orders:read"])


def test_full_client_credentials_flow():
    with TestClient(app) as client:
        response = client.post("/oauth/token", auth=(CLIENT_ID, SECRET),
                               data={"grant_type": "client_credentials", "scope": "orders:read"})
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        token = response.json()["access_token"]
        claims = verify_access_token(token)
        assert claims["client_id"] == CLIENT_ID
        assert claims["scope"] == "orders:read"
        allowed = client.get("/api/orders", headers={"Authorization": f"Bearer {token}"})
        assert allowed.status_code == 200
        assert allowed.json()["client_id"] == CLIENT_ID
        assert len(client.get("/.well-known/jwks.json").json()["keys"]) == 1


def test_bad_secret_and_bad_scope():
    with TestClient(app) as client:
        bad = client.post("/oauth/token", auth=(CLIENT_ID, "wrong"),
                          data={"grant_type": "client_credentials"})
        assert bad.status_code == 401
        assert bad.json() == {"error": "invalid_client"}
        invalid_scope = client.post("/oauth/token", auth=(CLIENT_ID, SECRET),
                                    data={"grant_type": "client_credentials", "scope": "admin"})
        assert invalid_scope.status_code == 400
        assert invalid_scope.json() == {"error": "invalid_scope"}


def test_default_scope_and_rejected_token():
    with TestClient(app) as client:
        response = client.post("/oauth/token", auth=(CLIENT_ID, SECRET),
                               data={"grant_type": "client_credentials"})
        assert response.json()["scope"] == "orders:read"
        assert client.get("/api/orders").status_code == 401
        assert client.get("/api/orders", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_scope_is_enforced():
    with TestClient(app) as client:
        response = client.post("/oauth/token", auth=(CLIENT_ID, SECRET),
                               data={"grant_type": "client_credentials", "scope": "orders:write"})
        assert response.status_code == 200
        token = response.json()["access_token"]
        denied = client.get("/api/orders", headers={"Authorization": f"Bearer {token}"})
        assert denied.status_code == 403


def test_deactivated_client_cannot_get_new_tokens():
    separate_id, separate_secret = create_client(["orders:read"], ["orders:read"])
    deactivate_client(separate_id)
    with TestClient(app) as client:
        response = client.post("/oauth/token", auth=(separate_id, separate_secret),
                               data={"grant_type": "client_credentials"})
        assert response.status_code == 401
