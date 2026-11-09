"""RFC 7662 introspection and RFC 7009 revocation for confidential clients."""
import base64
import binascii
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .config import settings
from .crypto import verify_access_token
from .db import DUMMY_HASH, OAuthClient, RevokedToken, audit, get_db, jti_hash, verify_secret
from .ratelimit import limit_token_requests

router = APIRouter()


def authenticate(request: Request, db: Session) -> OAuthClient:
    value = request.headers.get("Authorization", "")
    scheme, separator, encoded = value.partition(" ")
    if scheme.lower() != "basic" or not separator:
        raise HTTPException(401, "invalid_client", headers={"WWW-Authenticate": 'Basic realm="oauth"'})
    try:
        raw = base64.b64decode(encoded, validate=True).decode("utf-8")
        client_id, secret = raw.split(":", 1)
        client_id, secret = unquote_plus(client_id), unquote_plus(secret)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise HTTPException(401, "invalid_client")
    client = db.get(OAuthClient, client_id)
    valid = verify_secret(secret, client.secret_hash if client else DUMMY_HASH)
    if not client or not client.active or not valid:
        raise HTTPException(401, "invalid_client")
    return client


async def token_form(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
        raise HTTPException(400, "invalid_request")
    return await request.form()


@router.post("/oauth/introspect", dependencies=[Depends(limit_token_requests)])
async def introspect(request: Request, db: Session = Depends(get_db)):
    client = authenticate(request, db)
    form = await token_form(request)
    token = form.get("token")
    if not isinstance(token, str) or not token:
        raise HTTPException(400, "invalid_request")
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        audience = payload.get("aud")
        if not isinstance(audience, str) or audience not in client.resources.split():
            return {"active": False}
        claims = verify_access_token(token, audience=audience)
        if db.get(RevokedToken, jti_hash(claims["jti"])):
            return {"active": False}
        return {"active": True, "scope": claims.get("scope", ""), "client_id": claims["client_id"],
                "token_type": "Bearer", "sub": claims["sub"], "aud": claims["aud"],
                "iss": claims["iss"], "exp": claims["exp"], "iat": claims["iat"]}
    except (jwt.PyJWTError, TypeError, ValueError):
        return {"active": False}


@router.post("/oauth/revoke", dependencies=[Depends(limit_token_requests)])
async def revoke(request: Request, db: Session = Depends(get_db)):
    client = authenticate(request, db)
    form = await token_form(request)
    token = form.get("token")
    if not isinstance(token, str) or not token:
        raise HTTPException(400, "invalid_request")
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        audience = unverified.get("aud")
        if not isinstance(audience, str) or audience not in client.resources.split():
            return JSONResponse({}, headers={"Cache-Control": "no-store"})
        claims = verify_access_token(token, audience=audience)
        if claims["client_id"] == client.client_id:
            db.merge(RevokedToken(jti_hash=jti_hash(claims["jti"]),
                                  expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc)))
            audit(db, "token.revoked", client.client_id)
            db.commit()
    except (jwt.PyJWTError, TypeError, ValueError):
        pass
    # RFC 7009: return success even for invalid tokens.
    return JSONResponse({}, headers={"Cache-Control": "no-store"})
