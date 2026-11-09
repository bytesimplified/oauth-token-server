"""Security and interoperability checks beyond the happy-path smoke tests."""

import jwt
from fastapi.testclient import TestClient

from app.cli import create_client, rotate_client_secret
from app.crypto import key_id, private_key
from app.main import app


def issue(client, client_id, secret, **params):
    return client.post(
        "/oauth/token", auth=(client_id, secret),
        data={"grant_type": "client_credentials", **params},
    )


def test_missing_client_auth_and_invalid_grant():
    with TestClient(app) as http:
        unauthenticated = http.post("/oauth/token", data={"grant_type": "client_credentials"})
        assert unauthenticated.status_code == 401
        assert unauthenticated.headers["WWW-Authenticate"].startswith("Basic")
        unknown_grant = http.post("/oauth/token", data={"grant_type": "password"})
        assert unknown_grant.status_code == 400
        assert unknown_grant.json() == {"error": "unsupported_grant_type"}
        json_request = http.post("/oauth/token", json={"grant_type": "client_credentials"})
        assert json_request.status_code == 400
        assert json_request.json() == {"error": "invalid_request"}
        duplicate_grant = http.post(
            "/oauth/token",
            content="grant_type=client_credentials&grant_type=client_credentials",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert duplicate_grant.status_code == 400
        assert duplicate_grant.json() == {"error": "invalid_request"}


def test_jwks_verifies_token_and_tampering_is_rejected():
    client_id, secret = create_client(["orders:read"], ["orders:read"])
    with TestClient(app) as http:
        response = issue(http, client_id, secret)
        assert response.status_code == 200
        token = response.json()["access_token"]
        assert "client_secret" not in jwt.decode(token, options={"verify_signature": False})
        jwk = http.get("/.well-known/jwks.json").json()["keys"][0]
        public = jwt.PyJWK.from_dict(jwk).key
        metadata = http.get("/.well-known/oauth-authorization-server").json()
        claims = jwt.decode(token, public, algorithms=["RS256"], issuer=metadata["issuer"], audience="orders-api")
        assert claims["client_id"] == client_id
        assert jwt.get_unverified_header(token)["kid"] == jwk["kid"]
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
        assert http.get("/api/orders", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_invalid_audience_or_expired_token_rejected():
    client_id, secret = create_client(["orders:read"], ["orders:read"])
    with TestClient(app) as http:
        good_token = issue(http, client_id, secret).json()["access_token"]
        claims = jwt.decode(good_token, options={"verify_signature": False})
        claims["aud"] = "other-service"
        wrong_audience = jwt.encode(claims, private_key(), algorithm="RS256", headers={"typ": "at+jwt", "kid": key_id()})
        assert http.get("/api/orders", headers={"Authorization": f"Bearer {wrong_audience}"}).status_code == 401
        claims["aud"] = "orders-api"
        claims["exp"] = claims["iat"] - 10
        expired = jwt.encode(claims, private_key(), algorithm="RS256", headers={"typ": "at+jwt", "kid": key_id()})
        assert http.get("/api/orders", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_rotating_client_secret_disables_old_credentials():
    client_id, old_secret = create_client(["orders:read"], ["orders:read"])
    new_secret = rotate_client_secret(client_id)
    assert new_secret != old_secret
    with TestClient(app) as http:
        assert issue(http, client_id, old_secret).status_code == 401
        assert issue(http, client_id, new_secret).status_code == 200
