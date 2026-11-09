import base64
import binascii
import hashlib
import hmac
import secrets
from collections.abc import Iterator

from sqlalchemy import Boolean, String, create_engine
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


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


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


# Compute a dummy hash even for an unknown client ID to reduce timing leakage.
DUMMY_HASH = hash_secret("not-a-real-client-secret")
