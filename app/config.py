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
    admin_key: str = os.getenv("OAUTH_ADMIN_API_KEY", "")
    admin_ui_enabled: bool = os.getenv("OAUTH_ADMIN_UI_ENABLED", "false").lower() == "true"
    rate_limit: int = int(os.getenv("OAUTH_RATE_LIMIT_PER_MINUTE", "30"))
    trusted_proxy: bool = os.getenv("OAUTH_TRUST_PROXY", "false").lower() == "true"
    key_directory: str = os.getenv("OAUTH_KEY_DIRECTORY", "./keys")


settings = Config()
if not 60 <= settings.token_ttl <= 3600:
    raise ValueError("Token TTL must be between 60 and 3600 seconds")
if settings.rate_limit < 1:
    raise ValueError("Rate limit must be positive")
if not settings.issuer or not settings.audience:
    raise ValueError("OAUTH_ISSUER and OAUTH_AUDIENCE are required")
if settings.admin_ui_enabled and len(settings.admin_key) < 32:
    raise ValueError("Admin UI requires OAUTH_ADMIN_API_KEY of at least 32 characters")
