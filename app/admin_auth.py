"""OIDC bearer validation with remote JWKS and role-based authorization."""
import hmac

import jwt
from fastapi import Header, HTTPException

from .config import settings

_jwks_client = None


def require_admin(role: str = "admin"):
    def dependency(authorization: str | None = Header(default=None),
                   x_admin_key: str | None = Header(default=None)) -> dict:
        if settings.admin_oidc_issuer and settings.admin_oidc_audience and settings.admin_oidc_jwks_url:
            if not authorization or not authorization.startswith("Bearer "):
                raise HTTPException(401, "Admin bearer token required")
            try:
                global _jwks_client
                if _jwks_client is None:
                    _jwks_client = jwt.PyJWKClient(settings.admin_oidc_jwks_url, timeout=3)
                token = authorization[7:]
                key = _jwks_client.get_signing_key_from_jwt(token)
                claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=settings.admin_oidc_issuer,
                                    audience=settings.admin_oidc_audience,
                                    options={"require": ["exp", "iss", "aud", "sub"]})
                roles = claims.get(settings.admin_role_claim, [])
                if isinstance(roles, str):
                    roles = roles.split()
                if role not in roles and "admin" not in roles:
                    raise HTTPException(403, "Insufficient admin role")
                return claims
            except (jwt.PyJWTError, ValueError):
                raise HTTPException(401, "Invalid admin bearer token") from None
        if settings.production:
            raise HTTPException(503, "OIDC administrator authentication is required")
        if not settings.admin_key or len(settings.admin_key) < 32:
            raise HTTPException(503, "Admin API disabled; configure a strong admin key")
        if not x_admin_key or not hmac.compare_digest(x_admin_key, settings.admin_key):
            raise HTTPException(401, "Unauthorized")
        return {"sub": "development-admin", "roles": ["admin"]}
    return dependency
