# OAuth 2.0 Token Server

FastAPI OAuth 2.0 **Client Credentials** server for machine-to-machine API authentication. This repository includes a PostgreSQL deployment option, an authenticated administration API, optional browser dashboard, JWT access tokens, scope enforcement, revocation denylist, signing-key rotation, audit logs, and tests.

**Status:** Development reference. Not independently security-audited or production-ready. HTTPS, a shared distributed rate limiter, external key management, secret vault, and deployment hardening are required for internet-facing use.

## Start locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.cli generate-keys
alembic upgrade head
python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Store the generated client secret securely; it is displayed only once. To enable the admin API, set `OAUTH_ADMIN_API_KEY` to a strong random secret (32+ characters). To enable the browser UI also set `OAUTH_ADMIN_UI_ENABLED=true`. Environment variables are documented in `.env.example` and are not automatically loaded.

## Docker + PostgreSQL

Create a local `.env` containing a strong `POSTGRES_PASSWORD` and `OAUTH_ADMIN_API_KEY`. Never commit the file. Run:

```bash
mkdir -p keys
docker compose build
docker compose run --rm oauth python -m app.cli generate-keys
docker compose up -d
docker compose run --rm oauth python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
```

Docker Compose starts PostgreSQL 16 and runs Alembic migrations before launching the API. It binds the HTTP port to localhost only. Deploy behind HTTPS for remote access.

## Token issuance

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -d "grant_type=client_credentials&scope=orders:read" http://127.0.0.1:8000/oauth/token
```

Response: `{"access_token":"...","token_type":"Bearer","expires_in":600,"scope":"orders:read"}`.

Use the token:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/orders
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/oauth/token` | Client Credentials grant (HTTP Basic client auth) |
| GET | `/.well-known/jwks.json` | Public verification keys |
| GET | `/.well-known/oauth-authorization-server` | Server metadata |
| GET | `/api/orders` | Protected demo API; requires `orders:read` |
| GET | `/admin/clients` | List clients |
| POST | `/admin/clients` | Register client |
| PUT | `/admin/clients/{id}` | Update scopes/status |
| POST | `/admin/clients/{id}/rotate-secret` | Rotate secret |
| POST | `/admin/clients/{id}/deactivate` | Deactivate client |
| POST | `/admin/tokens/revoke` | Denylist token ID until expiry |
| GET | `/admin/audit` | Recent audit events |
| GET | `/admin/stats` | Basic usage counts |
| POST | `/admin/keys/rotate` | Replace active signing key; retain old public key |
| GET | `/admin/ui` | Optional browser dashboard |

Admin API requests require `X-Admin-Key: $OAUTH_ADMIN_API_KEY`; requests fail closed if the key is not configured. Protect admin endpoints using TLS, restricted network access, and preferably a real admin identity provider. The UI holds the supplied key only in the current page's memory, not local storage.

Example client registration:

```bash
curl -X POST http://127.0.0.1:8000/admin/clients \
  -H "X-Admin-Key: $OAUTH_ADMIN_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"scopes":["orders:read","orders:write"],"default_scopes":["orders:read"]}'
```

**Revocation:** `POST /admin/tokens/revoke` expects `{"jti":"<token-jti>","exp":<token-exp>}`. The admin must derive these values from a verified token. This endpoint is an internal administrative denylist operation, not the standard RFC 7009 token revocation endpoint. A revoked token is denied by the bundled example resource API. External APIs need their own revocation lookup or token introspection integration.

**Key rotation:** `POST /admin/keys/rotate` retains the old public key in the key directory so already-issued tokens can be verified. Back up the directory, coordinate multiple replicas, and remove retired keys only after their tokens expire. The implementation assumes one active signing instance.

**Rate limiting:** `/oauth/token` has an in-process, per-IP 60-second limiter. This is not distributed and must be replaced with Redis or a gateway limiter for multi-instance deployments. The server deliberately ignores client-supplied forwarded IP headers.

**Audit:** The database records client changes, successful and failed token requests, and key rotation. It never stores raw client secrets or token strings in audit records. The stats endpoint shows cumulative counts, not full analytics.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The existing flow/security tests plus admin and revocation tests are included. These changes should be tested in your deployment environment before promotion.

## Limitations

This is **Client Credentials only**. Refresh tokens and Authorization Code + PKCE are not included because they require additional user-oriented authorization flows. Token introspection, resource indicators, multiple audiences, user sessions, external KMS, distributed rate limiting, enterprise RBAC, and comprehensive client usage analytics remain future work. Client deactivation prevents **new** tokens, not existing JWTs; use the denylist to revoke an issued token.

See [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700).
