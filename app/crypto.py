import base64
import hashlib
import os
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
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with open(path, "xb", opener=lambda file, flags: os.open(file, flags, 0o600)) as handle:
        handle.write(pem)


def key_directory() -> Path:
    return Path(settings.private_key_path).parent


def _read_private(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def private_key():
    return _read_private(Path(settings.private_key_path))


def public_key():
    return private_key().public_key()


def _kid(public) -> str:
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:24]


def key_id() -> str:
    return _kid(public_key())


def b64url_int(number: int) -> str:
    return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def all_public_keys() -> dict:
    keys = {}
    for path in sorted(key_directory().glob("*.pem")):
        try:
            if path.resolve() == Path(settings.private_key_path).resolve():
                public = public_key()
            else:
                public = serialization.load_pem_public_key(path.read_bytes())
            keys[_kid(public)] = public
        except (ValueError, TypeError):
            continue
    keys[key_id()] = public_key()
    return keys


def jwks() -> dict:
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": b64url_int(public.public_numbers().n), "e": b64url_int(public.public_numbers().e),
    } for kid, public in all_public_keys().items()]}


def rotate_signing_key() -> str:
    """Retain previous public key for validation while replacing active private key."""
    path = Path(settings.private_key_path)
    previous = private_key()
    previous_kid = _kid(previous.public_key())
    previous_public_path = key_directory() / f"{previous_kid}.pem"
    if not previous_public_path.exists():
        previous_public_path.write_bytes(previous.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    with open(temp, "xb", opener=lambda file, flags: os.open(file, flags, 0o600)) as handle:
        handle.write(new_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    os.replace(temp, path)
    return _kid(new_key.public_key())


def make_access_token(client_id: str, scope: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.issuer, "sub": client_id, "aud": settings.audience,
        "client_id": client_id, "iat": int(now.timestamp()), "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.token_ttl)).timestamp()),
        "jti": secrets.token_urlsafe(20), "scope": scope,
    }
    key = private_key()
    return jwt.encode(payload, key, algorithm="RS256", headers={"typ": "at+jwt", "kid": _kid(key.public_key())})


def verify_access_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if header.get("typ") != "at+jwt":
        raise jwt.InvalidTokenError("Unexpected JWT header")
    key = all_public_keys().get(header.get("kid"))
    if key is None:
        raise jwt.InvalidTokenError("Unknown signing key")
    payload = jwt.decode(
        token, key, algorithms=["RS256"], audience=settings.audience, issuer=settings.issuer,
        options={"require": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id"]}, leeway=0,
    )
    if payload["sub"] != payload["client_id"]:
        raise jwt.InvalidTokenError("Client claim mismatch")
    return payload
