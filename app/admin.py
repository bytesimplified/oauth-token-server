import hmac
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .config import settings
from .crypto import rotate_signing_key
from .db import AuditEvent, OAuthClient, RevokedToken, audit, get_db, hash_secret, jti_hash

router = APIRouter(prefix="/admin", tags=["administration"])


def admin_auth(x_admin_key: str | None = Header(default=None)) -> None:
    if not settings.admin_key or len(settings.admin_key) < 32:
        raise HTTPException(503, "Admin API is disabled; configure a strong OAUTH_ADMIN_API_KEY")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, settings.admin_key):
        raise HTTPException(401, "Unauthorized")


class ClientCreate(BaseModel):
    scopes: list[str] = Field(min_length=1)
    default_scopes: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=lambda: [settings.audience])


class ClientUpdate(BaseModel):
    scopes: list[str] = Field(min_length=1)
    default_scopes: list[str] = Field(default_factory=list)
    active: bool = True


class RevokeRequest(BaseModel):
    jti: str = Field(min_length=1)
    exp: int


def check_scopes(scopes: list[str], defaults: list[str]) -> tuple[str, str]:
    allowed, default = set(scopes), set(defaults)
    configured = set(settings.allowed_scopes.split())
    if not allowed or not allowed <= configured or not default <= allowed:
        raise HTTPException(400, "Invalid scope configuration")
    return " ".join(sorted(allowed)), " ".join(sorted(default))


@router.get("/clients", dependencies=[Depends(admin_auth)])
def list_clients(db: Session = Depends(get_db)):
    return [{"client_id": c.client_id, "scopes": c.scopes.split(),
             "default_scopes": c.default_scopes.split(), "active": c.active,
             "resources": c.resources.split()}
            for c in db.scalars(select(OAuthClient).order_by(OAuthClient.client_id))]


@router.post("/clients", status_code=201, dependencies=[Depends(admin_auth)])
def create_client(data: ClientCreate, db: Session = Depends(get_db)):
    scopes, defaults = check_scopes(data.scopes, data.default_scopes)
    client_id = "cli_" + secrets.token_urlsafe(18)
    secret = "sec_" + secrets.token_urlsafe(32)
    db.add(OAuthClient(client_id=client_id, secret_hash=hash_secret(secret),
                       scopes=scopes, default_scopes=defaults, active=True,
                       resources=" ".join(sorted(set(data.resources)))))
    audit(db, "client.created", client_id)
    db.commit()
    return {"client_id": client_id, "client_secret": secret, "scopes": scopes.split()}


@router.put("/clients/{client_id}", dependencies=[Depends(admin_auth)])
def update_client(client_id: str, data: ClientUpdate, db: Session = Depends(get_db)):
    client = db.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    client.scopes, client.default_scopes = check_scopes(data.scopes, data.default_scopes)
    client.active = data.active
    client.resources = " ".join(sorted(set(data.resources)))
    audit(db, "client.updated", client_id)
    db.commit()
    return {"client_id": client_id, "active": client.active}


@router.post("/clients/{client_id}/rotate-secret", dependencies=[Depends(admin_auth)])
def rotate_secret(client_id: str, db: Session = Depends(get_db)):
    client = db.get(OAuthClient, client_id)
    if not client or not client.active:
        raise HTTPException(404, "Active client not found")
    secret = "sec_" + secrets.token_urlsafe(32)
    client.secret_hash = hash_secret(secret)
    audit(db, "client.secret_rotated", client_id)
    db.commit()
    return {"client_id": client_id, "client_secret": secret}


@router.post("/clients/{client_id}/deactivate", dependencies=[Depends(admin_auth)])
def deactivate(client_id: str, db: Session = Depends(get_db)):
    client = db.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    client.active = False
    audit(db, "client.deactivated", client_id)
    db.commit()
    return {"client_id": client_id, "active": False}


@router.post("/tokens/revoke", dependencies=[Depends(admin_auth)])
def revoke(data: RevokeRequest, db: Session = Depends(get_db)):
    expires = datetime.fromtimestamp(data.exp, timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise HTTPException(400, "Token already expired")
    db.merge(RevokedToken(jti_hash=jti_hash(data.jti), expires_at=expires))
    audit(db, "token.revoked")
    db.commit()
    return {"revoked": True}


@router.get("/audit", dependencies=[Depends(admin_auth)])
def audit_events(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit))
    return [{"id": e.id, "created_at": e.created_at.isoformat(),
             "event": e.event, "client_id": e.client_id, "detail": e.detail} for e in events]


@router.get("/stats", dependencies=[Depends(admin_auth)])
def stats(db: Session = Depends(get_db)):
    return {"clients": db.scalar(select(func.count()).select_from(OAuthClient)),
            "active_clients": db.scalar(select(func.count()).select_from(OAuthClient).where(OAuthClient.active.is_(True))),
            "audit_events": db.scalar(select(func.count()).select_from(AuditEvent)),
            "revoked_tokens": db.scalar(select(func.count()).select_from(RevokedToken))}


@router.post("/keys/rotate", dependencies=[Depends(admin_auth)])
def rotate_keys(db: Session = Depends(get_db)):
    kid = rotate_signing_key()
    audit(db, "signing_key.rotated")
    db.commit()
    return {"kid": kid}
