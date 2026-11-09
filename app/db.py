import base64
import binascii
import hashlib
import hmac
import secrets
from collections.abc import Iterator
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    client_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    scopes: Mapped[str] = mapped_column(String(1000), nullable=False)
    default_scopes: Mapped[str] = mapped_column(String(1000), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    event: Mapped[str] = mapped_column(String(80), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(String(255), default="")


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    jti_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    # For development only. In production run Alembic migrations before deployment.
    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


def audit(db: Session, event: str, client_id: str | None = None, detail: str = "") -> None:
    db.add(AuditEvent(event=event, client_id=client_id, detail=detail[:255]))


def jti_hash(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(salt).decode() + ":" + base64.urlsafe_b64encode(digest).decode()


def verify_secret(secret: str, stored: str) -> bool:
    try:
        salt_string, hash_string = stored.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_string)
        expected = base64.urlsafe_b64decode(hash_string)
        actual = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, binascii.Error):
        return False


DUMMY_HASH = hash_secret("not-a-real-client-secret")
