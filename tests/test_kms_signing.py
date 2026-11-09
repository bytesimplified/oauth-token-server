"""AWS KMS signature round-trip without requiring AWS credentials."""
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


def test_kms_signing_and_jwks(monkeypatch):
    from app import crypto, kms_signing

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    arn = "arn:aws:kms:us-east-1:123456789012:key/abc123"
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    class MockKMS:
        def get_public_key(self, KeyId):
            assert KeyId == arn
            return {"PublicKey": pub, "KeyUsage": "SIGN_VERIFY",
                    "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"]}

        def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
            assert KeyId == arn and MessageType == "DIGEST"
            assert SigningAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256"
            return {"Signature": key.sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))}

    monkeypatch.setattr(kms_signing, "client", lambda: MockKMS())
    kms_signing.public_key_for.cache_clear()
    monkeypatch.setattr(kms_signing, "settings", SimpleNamespace(kms_key_id=arn, kms_verify_key_ids=""))
    monkeypatch.setattr(crypto, "settings", SimpleNamespace(
        kms_key_id=arn, issuer="http://127.0.0.1:8000", audience="orders-api", token_ttl=600,
    ))
    try:
        token = crypto.make_access_token("sample", "orders:read")
        claims = crypto.verify_access_token(token)
        assert claims["client_id"] == "sample"
        assert crypto.jwks()["keys"][0]["kid"] == jwt.get_unverified_header(token)["kid"]
    finally:
        kms_signing.public_key_for.cache_clear()
