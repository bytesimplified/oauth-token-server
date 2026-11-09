# OAuth 2.0 Token Server

FastAPI machine-to-machine OAuth server implementing the Client Credentials grant, RS256 JWT access tokens, client registration and management, PostgreSQL/Alembic, Redis rate limiting, OAuth introspection and revocation, per-client resource audiences, an optional development admin UI, audit events, Prometheus metrics, and GitHub Actions CI.

**Security status:** This is an evolving reference implementation, **not a certified production identity provider**. CI and integration results must be checked before deployment. In particular, multi-instance KMS/HSM-backed signing, production-grade administrative identity/roles, TLS ingress, and full deployment testing still require environment-specific work.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.cli generate-keys
alembic upgrade head
python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
uvicorn app.main:app --host 127.0.0.1 --port 8000
pytest -q
```

The `OAUTH_*` settings are described in `.env.example`. Environment variables must be exported by your shell or supplied by your deployment; the example file is not loaded automatically. The admin API uses a strong `OAUTH_ADMIN_API_KEY` in development. Enable the development dashboard with `OAUTH_ADMIN_UI_ENABLED=true` and visit `/admin/ui`.

## PostgreSQL + Redis via Docker

Create a local `.env` file containing `POSTGRES_PASSWORD`, `OAUTH_ADMIN_API_KEY` (at least 32 random characters), and `OAUTH_METRICS_KEY`. Never commit the file.

```bash
mkdir -p keys
docker compose build
docker compose run --rm oauth python -m app.cli generate-keys
docker compose up -d
docker compose run --rm oauth python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
```

Docker Compose binds the HTTP port to localhost and is **development only**. It uses PostgreSQL 16, Redis 7, and applies Alembic migrations. Production deployments must use HTTPS at an ingress, restrict internal network access, supply managed secrets and backups, and set `OAUTH_ENV=production` with a PostgreSQL URL, Redis URL, HTTPS issuer, and admin OIDC configuration.

## OAuth endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/oauth/token` | Client Credentials access token |
| POST | `/oauth/introspect` | RFC 7662 active status and claims |
| POST | `/oauth/revoke` | RFC 7009 revocation of caller-owned tokens |
| GET | `/.well-known/jwks.json` | Signing public keys |
| GET | `/.well-known/oauth-authorization-server` | OAuth discovery metadata |
| GET | `/api/orders` | Example protected API |

Example:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=orders:read" \
  http://127.0.0.1:8000/oauth/token
```

For resource-specific access tokens, include `resource=orders-api`. Each client has a configurable set of permitted resource audiences. External resource servers should validate JWTs against the expected audience and JWKS and, when immediate revocation is necessary, consult the introspection endpoint.

## Admin API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/clients` | List clients and allowed audiences |
| POST | `/admin/clients` | Create client; returns secret once |
| PUT | `/admin/clients/{id}` | Update scopes, resources, status |
| POST | `/admin/clients/{id}/rotate-secret` | Rotate secret |
| POST | `/admin/clients/{id}/deactivate` | Disable client |
| POST | `/admin/tokens/revoke` | Internal token-ID denylist |
| GET | `/admin/audit` | Recent audit events |
| GET | `/admin/stats` | Basic usage counts |
| POST | `/admin/keys/rotate` | Rotate signing key |
| GET | `/admin/ui` | Optional development-only dashboard |
| GET | `/internal/metrics` | Prometheus metrics (X-Metrics-Key) |

Development administration uses `X-Admin-Key`. For production, set `OAUTH_ADMIN_OIDC_ISSUER`, `OAUTH_ADMIN_OIDC_AUDIENCE`, and `OAUTH_ADMIN_OIDC_JWKS_URL` and send `Authorization: Bearer <admin-idp-token>`. The token must have a `roles` claim containing `admin` (configurable claim name). The application validates signature, issuer, audience and expiration using the configured identity provider's JWKS. Restrict the admin API to trusted networks and use an identity provider that issues appropriately scoped administrator tokens.

The `/admin/ui` key-entry page is intentionally disabled in production; integrate a secure OIDC admin frontend instead.

## Security and operations

- Secrets are scrypt-hashed. Never log client secrets or tokens.
- Access tokens expire after 600 seconds by default.
- Redis provides a shared per-IP fixed-window rate limiter for token, introspection and revocation endpoints. Configure a trusted ingress to preserve meaningful client IPs; never trust arbitrary forwarded headers.
- Token introspection and revocation require valid confidential-client credentials. Revocation is limited to tokens owned by the caller.
- Token revocation records are stored in PostgreSQL and checked by the bundled protected API.
- Audit events capture token issuance/denials and administrative changes; metrics expose token outcomes and admin action counts.
- Signing key rotation retains previous public keys so issued JWTs remain verifiable until expiry. The local filesystem rotation mechanism is single-instance; use centralized KMS/HSM and controlled key lifecycle before multi-instance production use.
- Production configuration fails fast if HTTPS issuer, PostgreSQL, Redis, or OIDC administrator settings are missing. It does **not** provision TLS, an OIDC provider, a KMS, or backups for you.
- CI runs tests, a dependency audit, and a Docker build; check GitHub Actions results before release.

## Not included

Authorization Code + PKCE, OpenID Connect, refresh tokens, mTLS, private-key JWT client authentication, full multi-tenant RBAC, distributed signing-key management, browser-based OIDC admin login, end-to-end TLS deployment, and detailed per-client trend analytics.

References: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700).
