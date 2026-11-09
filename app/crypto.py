import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import settings


def generate_private_key(output: str) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "xb", opener=lambda file, flags: __import__("os").open(file, flags, 0o600)) as handle:
        handle.write(pem)


@lru_cache(maxsize=1)
def private_key():
    with open(settings.private_key_path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


@lru_cache(maxsize=1)
def public_key():
    return private_key().public_key()


def key_id() -> str:
    der = public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:24]


def b64url_int(number: int) -> str:
    return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def jwks() -> dict:
    numbers = public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": key_id(),
        "n": b64url_int(numbers.n), "e": b64url_int(numbers.e),
    }]}


def make_access_token(client_id: str, scope: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.issuer,
        "sub": client_id,
        "aud": settings.audience,
        "client_id": client_id,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.token_ttl)).timestamp()),
        "jti": secrets.token_urlsafe(20),
        "scope": scope,
    }
    return jwt.encode(payload, private_key(), algorithm="RS256", headers={"typ": "at+jwt", "kid": key_id()})


def verify_access_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if header.get("typ") != "at+jwt" or header.get("kid") != key_id():
        raise jwt.InvalidTokenError("Unexpected JWT header")
    payload = jwt.decode(
        token, public_key(), algorithms=["RS256"],
        audience=settings.audience, issuer=settings.issuer,
        options={"require": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id"]},
        leeway=0,
    )
    if payload["sub"] != payload["client_id"]:
        raise jwt.InvalidTokenError("Client claim mismatch")
    return payload
