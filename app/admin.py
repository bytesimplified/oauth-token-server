import hmac
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .config import settings
from .admin_auth import require_admin
from .metrics import admin_actions
from .crypto import rotate_signing_key
from .db import AuditEvent, OAuthClient, RevokedToken, audit, get_db, hash_secret, jti_hash

router = APIRouter(prefix="/admin", tags=["administration"])




class ClientCreate(BaseModel):
    scopes: list[str] = Field(min_length=1)
    default_scopes: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=lambda: [settings.audience])


class ClientUpdate(BaseModel):
    scopes: list[str] = Field(min_length=1)
    default_scopes: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=lambda: [settings.audience])
    active: bool = True


class RevokeRequest(BaseModel):
    jti: str = Field(min_length=1)
    exp: int


def check_resources(resources: list[str]) -> None:
    if not resources or len(resources) > 20 or any(not r or len(r) > 200 or any(c.isspace() for c in r) for r in resources):
        raise HTTPException(400, "Invalid resource audiences")


def check_scopes(scopes: list[str], defaults: list[str]) -> tuple[str, str]:
    allowed, default = set(scopes), set(defaults)
    configured = set(settings.allowed_scopes.split())
    if not allowed or not allowed <= configured or not default <= allowed:
        raise HTTPException(400, "Invalid scope configuration")
    return " ".join(sorted(allowed)), " ".join(sorted(default))


@router.get("/clients", dependencies=[Depends(require_admin("viewer"))])
def list_clients(db: Session = Depends(get_db)):
    return [{"client_id": c.client_id, "scopes": c.scopes.split(),
             "default_scopes": c.default_scopes.split(), "active": c.active,
             "resources": c.resources.split()}
            for c in db.scalars(select(OAuthClient).order_by(OAuthClient.client_id))]


@router.post("/clients", status_code=201, dependencies=[Depends(require_admin())])
def create_client(data: ClientCreate, db: Session = Depends(get_db)):
    scopes, defaults = check_scopes(data.scopes, data.default_scopes)
    check_resources(data.resources)
    client_id = "cli_" + secrets.token_urlsafe(18)
    secret = "sec_" + secrets.token_urlsafe(32)
    db.add(OAuthClient(client_id=client_id, secret_hash=hash_secret(secret),
                       scopes=scopes, default_scopes=defaults, active=True,
                       resources=" ".join(sorted(set(data.resources)))))
    audit(db, "client.created", client_id)
    admin_actions.labels("client.created").inc()
    db.commit()
    return {"client_id": client_id, "client_secret": secret, "scopes": scopes.split()}


@router.put("/clients/{client_id}", dependencies=[Depends(require_admin())])
def update_client(client_id: str, data: ClientUpdate, db: Session = Depends(get_db)):
    client = db.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    client.scopes, client.default_scopes = check_scopes(data.scopes, data.default_scopes)
    check_resources(data.resources)
    client.active = data.active
    client.resources = " ".join(sorted(set(data.resources)))
    audit(db, "client.updated", client_id)
    admin_actions.labels("client.updated").inc()
    db.commit()
    return {"client_id": client_id, "active": client.active}


@router.post("/clients/{client_id}/rotate-secret", dependencies=[Depends(require_admin())])
def rotate_secret(client_id: str, db: Session = Depends(get_db)):
    client = db.get(OAuthClient, client_id)
    if not client or not client.active:
        raise HTTPException(404, "Active client not found")
    secret = "sec_" + secrets.token_urlsafe(32)
    client.secret_hash = hash_secret(secret)
    audit(db, "client.secret_rotated", client_id)
    admin_actions.labels("client.secret_rotated").inc()
    db.commit()
    return {"client_id": client_id, "client_secret": secret}


@router.post("/clients/{client_id}/deactivate", dependencies=[Depends(require_admin())])
def deactivate(client_id: str, db: Session = Depends(get_db)):
    client = db.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    client.active = False
    audit(db, "client.deactivated", client_id)
    admin_actions.labels("client.deactivated").inc()
    db.commit()
    return {"client_id": client_id, "active": False}


@router.post("/tokens/revoke", dependencies=[Depends(require_admin())])
def revoke(data: RevokeRequest, db: Session = Depends(get_db)):
    expires = datetime.fromtimestamp(data.exp, timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise HTTPException(400, "Token already expired")
    db.merge(RevokedToken(jti_hash=jti_hash(data.jti), expires_at=expires))
    audit(db, "token.revoked")
    admin_actions.labels("token.revoked").inc()
    db.commit()
    return {"revoked": True}


@router.get("/audit", dependencies=[Depends(require_admin("viewer"))])
def audit_events(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit))
    return [{"id": e.id, "created_at": e.created_at.isoformat(),
             "event": e.event, "client_id": e.client_id, "detail": e.detail} for e in events]


@router.get("/stats", dependencies=[Depends(require_admin("viewer"))])
def stats(db: Session = Depends(get_db)):
    return {"clients": db.scalar(select(func.count()).select_from(OAuthClient)),
            "active_clients": db.scalar(select(func.count()).select_from(OAuthClient).where(OAuthClient.active.is_(True))),
            "audit_events": db.scalar(select(func.count()).select_from(AuditEvent)),
            "revoked_tokens": db.scalar(select(func.count()).select_from(RevokedToken))}


@router.post("/keys/rotate", dependencies=[Depends(require_admin())])
def rotate_keys(db: Session = Depends(get_db)):
    if settings.kms_key_id:
        raise HTTPException(409, "KMS key rotation requires deployment rollout; retain old key ARNs until access tokens expire")
    kid = rotate_signing_key()
    audit(db, "signing_key.rotated")
    admin_actions.labels("signing_key.rotated").inc()
    db.commit()
    return {"kid": kid}
