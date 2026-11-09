import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    issuer: str = os.getenv("OAUTH_ISSUER", "http://127.0.0.1:8000").rstrip("/")
    audience: str = os.getenv("OAUTH_AUDIENCE", "orders-api")
    database_url: str = os.getenv("OAUTH_DB_URL", "sqlite:///./oauth.db")
    private_key_path: str = os.getenv("OAUTH_PRIVATE_KEY_PATH", "./keys/private.pem")
    token_ttl: int = int(os.getenv("OAUTH_TOKEN_TTL_SECONDS", "600"))
    allowed_scopes: str = os.getenv("OAUTH_ALLOWED_SCOPES", "orders:read orders:write")


settings = Config()

if not 60 <= settings.token_ttl <= 3600:
    raise ValueError("Token TTL must be between 60 and 3600 seconds")
if not settings.issuer or not settings.audience:
    raise ValueError("OAUTH_ISSUER and OAUTH_AUDIENCE are required")
