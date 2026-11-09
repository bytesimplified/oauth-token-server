"""Unit security checks using fake cloud dependencies; no AWS account required."""
import json
import os
import time
from types import SimpleNamespace

import boto3
import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from fastapi.testclient import TestClient

from app import admin_auth, crypto, kms_signing
from app.main import app
from app.secret_loader import load_aws_secrets


def test_secret_manager_loads_only_allowlisted_secrets(monkeypatch):
    class FakeSecrets:
        def get_secret_value(self, SecretId):
            assert SecretId == "arn:aws:secretsmanager:us-east-1:123456789012:secret:oauth"
            return {"SecretString": json.dumps({"OAUTH_DB_URL": "postgresql+psycopg://test"})}

    monkeypatch.setenv("OAUTH_AWS_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:oauth")
    monkeypatch.setattr(boto3, "client", lambda service: FakeSecrets() if service == "secretsmanager" else None)
    load_aws_secrets()
    assert os.getenv("OAUTH_DB_URL") == "postgresql+psycopg://test"

    class BadSecrets:
        def get_secret_value(self, SecretId):
            return {"SecretString": json.dumps({"UNEXPECTED_SECRET": "bad"})}

    monkeypatch.setattr(boto3, "client", lambda service: BadSecrets())
    with pytest.raises(ValueError, match="unknown keys"):
        load_aws_secrets()


def test_kms_rollover_keeps_old_tokens_verifiable(monkeypatch):
    arns = [
        "arn:aws:kms:us-east-1:123456789012:key/active-v1",
        "arn:aws:kms:us-east-1:123456789012:key/active-v2",
    ]
    private = {arn: rsa.generate_private_key(public_exponent=65537, key_size=2048) for arn in arns}
    public = {arn: p.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ) for arn, p in private.items()}

    class FakeKMS:
        def get_public_key(self, KeyId):
            return {"PublicKey": public[KeyId], "KeyUsage": "SIGN_VERIFY",
                    "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"]}

        def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
            assert MessageType == "DIGEST" and SigningAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256"
            return {"Signature": private[KeyId].sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))}

    config = SimpleNamespace(kms_key_id=arns[0], kms_verify_key_ids="",
                             issuer="http://127.0.0.1:8000", audience="orders-api", token_ttl=600)
    monkeypatch.setattr(kms_signing, "settings", config)
    monkeypatch.setattr(crypto, "settings", config)
    monkeypatch.setattr(kms_signing, "client", lambda: FakeKMS())
    kms_signing.public_key_for.cache_clear()
    try:
        first = crypto.make_access_token("client", "orders:read")
        config.kms_key_id = arns[1]
        config.kms_verify_key_ids = arns[0]
        second = crypto.make_access_token("client", "orders:read")
        assert jwt.get_unverified_header(first)["kid"] != jwt.get_unverified_header(second)["kid"]
        assert crypto.verify_access_token(first)["client_id"] == "client"
        assert crypto.verify_access_token(second)["client_id"] == "client"
        assert len(crypto.jwks()["keys"]) == 2
    finally:
        kms_signing.public_key_for.cache_clear()


def test_oidc_admin_roles_and_token_validation(monkeypatch):
    issuer, audience = "https://idp.example", "oauth-admin"

    class TestJwks:
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=crypto.private_key().public_key())

    config = SimpleNamespace(admin_oidc_issuer=issuer, admin_oidc_audience=audience,
                             admin_oidc_jwks_url=issuer + "/jwks",
                             admin_role_claim="roles", production=True)
    monkeypatch.setattr(admin_auth, "settings", config)
    monkeypatch.setattr(admin_auth, "_jwks_client", TestJwks())

    def token(role, aud=audience):
        return jwt.encode({"iss": issuer, "aud": aud, "sub": "admin-user",
                           "exp": int(time.time()) + 600, "roles": [role]},
                          crypto.private_key(), algorithm="RS256", headers={"kid": "test-key"})

    with TestClient(app) as http:
        viewer = {"Authorization": "Bearer " + token("viewer")}
        administrator = {"Authorization": "Bearer " + token("admin")}
        assert http.get("/admin/stats", headers=viewer).status_code == 200
        creation = {"scopes": ["orders:read"], "default_scopes": ["orders:read"]}
        assert http.post("/admin/clients", headers=viewer, json=creation).status_code == 403
        assert http.post("/admin/clients", headers=administrator, json=creation).status_code == 201
        assert http.get("/admin/stats", headers={"Authorization": "Bearer " + token("admin", "bad-audience")}).status_code == 401
        assert http.get("/admin/stats", headers={"X-Admin-Key": "unused-key"}).status_code == 401
