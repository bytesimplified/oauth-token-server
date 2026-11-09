"""AWS KMS asymmetric RS256 token signing; private material never leaves KMS.

Use *immutable key ARNs* rather than aliases. Rotate by deploying a new active
ARN and retaining old ARNs in OAUTH_KMS_VERIFY_KEY_IDS through token expiry.
"""
import base64
from functools import lru_cache
import hashlib
import json

import boto3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import settings


@lru_cache(maxsize=1)
def client():
    return boto3.client("kms")


@lru_cache(maxsize=64)
def public_key_for(key_arn: str):
    result = client().get_public_key(KeyId=key_arn)
    if result.get("KeyUsage") != "SIGN_VERIFY" or "RSASSA_PKCS1_V1_5_SHA_256" not in result.get("SigningAlgorithms", []):
        raise ValueError("KMS key must be an RSA SIGN_VERIFY key supporting SHA-256 / PKCS#1 v1.5")
    public = serialization.load_der_public_key(result["PublicKey"])
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
        raise ValueError("KMS public key must be RSA 2048-bit or stronger")
    return public


def kid(public) -> str:
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:24]


def permitted_key_ids() -> list[str]:
    identifiers = [settings.kms_key_id]
    identifiers += [part.strip() for part in settings.kms_verify_key_ids.split(",") if part.strip()]
    if not all(x.startswith("arn:") and ":kms:" in x and ":key/" in x for x in identifiers):
        raise ValueError("Configure immutable AWS KMS key ARNs, not aliases")
    return list(dict.fromkeys(identifiers))


def kms_public_keys() -> dict:
    return {kid(public_key_for(arn)): public_key_for(arn) for arn in permitted_key_ids()}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def kms_sign_payload(payload: dict) -> str:
    public = public_key_for(settings.kms_key_id)
    header = {"alg": "RS256", "typ": "at+jwt", "kid": kid(public)}
    head = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    body = b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = (head + "." + body).encode("ascii")
    digest = hashlib.sha256(signing_input).digest()
    result = client().sign(
        KeyId=settings.kms_key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    return signing_input.decode() + "." + b64url(result["Signature"])
