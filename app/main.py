import base64
from contextlib import asynccontextmanager
import binascii
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .admin import router as admin_router
from .config import settings
from .crypto import jwks, make_access_token, public_key, verify_access_token
from .health import router as health_router
from .analytics import router as analytics_router
from .dashboard import router as dashboard_router
from .db import DUMMY_HASH, OAuthClient, RevokedToken, audit, get_db, init_db, jti_hash, verify_secret
from .ratelimit import limit_token_requests
from .metrics import router as metrics_router, token_requests, observe_request
from .oauth_extensions import router as oauth_extensions_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    public_key()
    init_db()
    yield


app = FastAPI(title="OAuth 2.0 Client Credentials Server", version="2.0.0", lifespan=lifespan)
app.include_router(admin_router)
app.include_router(dashboard_router)
app.include_router(metrics_router)
app.include_router(health_router)
app.include_router(analytics_router)
app.middleware('http')(observe_request)
app.include_router(oauth_extensions_router)
bearer_scheme = HTTPBearer(auto_error=False)


class OAuthError(Exception):
    def __init__(self, code: str, status_code: int = 400):
        self.code, self.status_code = code, status_code


@app.exception_handler(OAuthError)
def oauth_error_handler(_request: Request, exc: OAuthError):
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    if exc.code == "invalid_client":
        headers["WWW-Authenticate"] = 'Basic realm="oauth/token"'
    return JSONResponse(status_code=exc.status_code, content={"error": exc.code}, headers=headers)


def client_basic_auth(request: Request) -> tuple[str, str]:
    value = request.headers.get("Authorization", "")
    scheme, separator, credentials = value.partition(" ")
    if separator != " " or scheme.lower() != "basic":
        raise OAuthError("invalid_client", 401)
    try:
        decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
        client_id, client_secret = unquote_plus(client_id), unquote_plus(client_secret)
        if not client_id or not client_secret:
            raise ValueError("Empty credentials")
        return client_id, client_secret
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise OAuthError("invalid_client", 401) from None


@app.post("/oauth/token", dependencies=[Depends(limit_token_requests)])
async def token(request: Request, response: Response, db: Session = Depends(get_db)):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise OAuthError("invalid_request")
    form = await request.form()
    if len(form.getlist("grant_type")) != 1 or len(form.getlist("scope")) > 1:
        raise OAuthError("invalid_request")
    if form.get("grant_type") != "client_credentials":
        raise OAuthError("unsupported_grant_type")
    client_id, client_secret = client_basic_auth(request)
    client = db.get(OAuthClient, client_id)
    good_secret = verify_secret(client_secret, client.secret_hash if client else DUMMY_HASH)
    if client is None or not client.active or not good_secret:
        audit(db, "token.denied", client_id, "invalid_client")
        token_requests.labels("invalid_client").inc()
        db.commit()
        raise OAuthError("invalid_client", 401)
    requested = form.get("scope")
    if requested is not None and not isinstance(requested, str):
        raise OAuthError("invalid_request")
    scopes = set(requested.split()) if requested is not None else set(client.default_scopes.split())
    if not scopes <= set(client.scopes.split()):
        audit(db, "token.denied", client_id, "invalid_scope")
        token_requests.labels("invalid_scope").inc()
        db.commit()
        raise OAuthError("invalid_scope")
    scope = " ".join(sorted(scopes))
    resource = form.get("resource")
    if len(form.getlist("resource")) > 1 or (resource is not None and not isinstance(resource, str)):
        raise OAuthError("invalid_request")
    audience = resource or settings.audience
    if audience not in set(client.resources.split()):
        raise OAuthError("invalid_target")
    access_token = make_access_token(client_id, scope, audience)
    audit(db, "token.issued", client_id, scope)
    token_requests.labels("issued").inc()
    db.commit()
    response.headers.update({"Cache-Control": "no-store", "Pragma": "no-cache"})
    return {"access_token": access_token, "token_type": "Bearer", "expires_in": settings.token_ttl, "scope": scope}


@app.get("/.well-known/jwks.json")
def public_jwks():
    return jwks()


@app.get("/.well-known/oauth-authorization-server")
def metadata():
    return {"issuer": settings.issuer, "token_endpoint": settings.issuer + "/oauth/token",
            "jwks_uri": settings.issuer + "/.well-known/jwks.json",
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "scopes_supported": settings.allowed_scopes.split(),
            "revocation_endpoint": settings.issuer + "/oauth/revoke",
            "introspection_endpoint": settings.issuer + "/oauth/introspect"}


def require_scope(scope: str, audience: str | None = None):
    def dependency(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
                   db: Session = Depends(get_db)) -> dict:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="missing_token", headers={"WWW-Authenticate": "Bearer"})
        try:
            claims = verify_access_token(credentials.credentials, audience=audience)
        except (jwt.PyJWTError, ValueError, TypeError):
            raise HTTPException(status_code=401, detail="invalid_token",
                                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}) from None
        if db.get(RevokedToken, jti_hash(claims["jti"])) is not None:
            raise HTTPException(status_code=401, detail="revoked_token",
                                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        if scope not in claims.get("scope", "").split():
            raise HTTPException(status_code=403, detail="insufficient_scope",
                                headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'})
        return claims
    return dependency


@app.get("/api/orders")
def protected_orders(claims: dict = Depends(require_scope("orders:read"))):
    return {"message": "Authorized request", "client_id": claims["client_id"], "orders": []}
