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
    redis_url: str = os.getenv("OAUTH_REDIS_URL", "")
    key_directory: str = os.getenv("OAUTH_KEY_DIRECTORY", "./keys")
    production: bool = os.getenv("OAUTH_ENV", "development").lower() == "production"
    admin_oidc_issuer: str = os.getenv("OAUTH_ADMIN_OIDC_ISSUER", "").rstrip("/")
    admin_oidc_audience: str = os.getenv("OAUTH_ADMIN_OIDC_AUDIENCE", "")
    admin_oidc_jwks_url: str = os.getenv("OAUTH_ADMIN_OIDC_JWKS_URL", "")
    admin_role_claim: str = os.getenv("OAUTH_ADMIN_ROLE_CLAIM", "roles")
    metrics_key: str = os.getenv("OAUTH_METRICS_KEY", "")


settings = Config()
if not 60 <= settings.token_ttl <= 3600:
    raise ValueError("Token TTL must be between 60 and 3600 seconds")
if settings.rate_limit < 1:
    raise ValueError("Rate limit must be positive")
if not settings.issuer or not settings.audience:
    raise ValueError("Issuer and audience are required")
if settings.production:
    if not settings.issuer.startswith("https://"):
        raise ValueError("Production issuer must use HTTPS")
    if not settings.database_url.startswith("postgresql+psycopg://"):
        raise ValueError("Production requires PostgreSQL")
    if not settings.redis_url:
        raise ValueError("Production requires Redis rate limiting")
    if not (settings.admin_oidc_issuer and settings.admin_oidc_audience and settings.admin_oidc_jwks_url):
        raise ValueError("Production requires OIDC admin authentication")
    if settings.admin_ui_enabled:
        raise ValueError("The key-entry admin dashboard is disabled in production")
