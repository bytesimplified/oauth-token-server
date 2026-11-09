# OAuth 2.0 Authorization / Token Server

A FastAPI OAuth 2.0 **Client Credentials** authorization server with RS256 JWT access tokens, scope- and resource-restricted authorization, client management, introspection, revocation, administration, and production-hardening integrations.

> **Deployment status:** Code and infrastructure examples are in this repository. A secure live deployment is **not** created by cloning it. Cloud resources, a real OIDC administrator identity provider, DNS/TLS, backups, and security review must be configured and verified for your environment.

## Capabilities

- **OAuth:** `POST /oauth/token` (client-secret Basic auth), RS256 JWTs, JWKS, metadata, token introspection (RFC 7662), revocation (RFC 7009), and resource indicators (RFC 8707).
- **Management:** Register, update, deactivate, and rotate client secrets using REST APIs or the CLI; scoped admin permissions via external OIDC.
- **Storage:** SQLite for local development; PostgreSQL with Alembic migrations for deployed environments. Secrets use salted scrypt hashes.
- **Protection:** Redis-backed shared rate limiting, revocation denylist, audit trail, and per-client resource audiences.
- **Signing:** Local PEM in development; AWS KMS asymmetric signing in production, including verification of retired keys without exporting private keys.
- **Secrets:** AWS Secrets Manager runtime secret loading via IAM role. No production database passwords in Terraform state.
- **Operations:** Health endpoints, Prometheus metrics, hourly client-activity analytics, alert-rule examples, encrypted PostgreSQL backup/restore scripts, audit retention, and CI with real PostgreSQL + Redis integration tests.
- **HTTPS:** Example Caddy automatic-TLS single-host deployment; use your own managed ingress/orchestrator for high availability.

## Local quick start (Python 3.12)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.cli generate-keys
alembic upgrade head
python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Copy the client ID and secret printed by the CLI; the secret is shown only once. The `OAUTH_*` configuration variables are in `.env.example`; export them or use a process manager (the file is not automatically loaded). The database and generated signing keys are excluded from Git.

### Exercise the OAuth flow

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d 'grant_type=client_credentials&scope=orders:read&resource=orders-api' \
  http://127.0.0.1:8000/oauth/token
```

Then call `GET /api/orders` with `Authorization: Bearer <access_token>`.

### Local PostgreSQL + Redis via Docker Compose

Create a local `.env` with strong `POSTGRES_PASSWORD`, `OAUTH_ADMIN_API_KEY` (32+ random characters), and `OAUTH_METRICS_KEY`, then:

```bash
mkdir -p keys
docker compose build
docker compose run --rm oauth python -m app.cli generate-keys
docker compose up -d
docker compose run --rm oauth python -m app.cli create-client --scopes orders:read --default-scopes orders:read
```

This Compose stack is **HTTP loopback development only**.

## OAuth and administration endpoints

| Route | Purpose |
| --- | --- |
| `POST /oauth/token` | Client Credentials access tokens |
| `POST /oauth/introspect` | Active status and token claims |
| `POST /oauth/revoke` | Caller-owned token revocation |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /.well-known/oauth-authorization-server` | Discovery |
| `GET /api/orders` | Protected example resource |
| `GET /admin/clients` | Client list |
| `POST /admin/clients` | Client registration |
| `PUT /admin/clients/{id}` | Update scopes/resources/active status |
| `POST /admin/clients/{id}/rotate-secret` | Client-secret rotation |
| `POST /admin/clients/{id}/deactivate` | Deactivate client |
| `POST /admin/tokens/revoke` | Internal JTI denylist |
| `GET /admin/audit` | Audit log |
| `GET /admin/stats` | Cumulative counts |
| `GET /admin/analytics?hours=24` | Per-client hourly issuance/denial counts |
| `POST /admin/keys/rotate` | Local dev key rotation only |
| `GET /health/live`, `GET /health/ready` | Health checks |
| `GET /internal/metrics` | Protected Prometheus metrics |

In development, configure `OAUTH_ADMIN_API_KEY` and supply `X-Admin-Key` to administrative endpoints. In production, configure OIDC and supply `Authorization: Bearer <admin-identity-token>`. Mutations require the `admin` role; read-only administration allows `viewer` or `admin`. `/admin/ui` remains a **development-only** key-entry interface and is disabled in production.

## Production deployment

See **[Production deployment and key-rotation guide](docs/production-deployment.md)**, **[Production checklist](docs/production-checklist.md)**, `infra/aws` for KMS/Secrets Manager/IAM Terraform, `deploy/compose.production.yaml` and `deploy/Caddyfile` for TLS, and `monitoring` for Prometheus alert rules.

Production requires `OAUTH_ENV=production`, HTTPS `OAUTH_ISSUER`, PostgreSQL, Redis, AWS KMS key ARN, AWS Secrets Manager secret ARN, and OIDC administrator authentication configuration. These are validated at startup. **AWS credentials must be provided through an IAM workload role**; do not place long-lived AWS access keys in the repository or container configuration.

To rotate the signing key, provision a new KMS asymmetric RSA signing key, put its immutable ARN in `OAUTH_KMS_KEY_ID`, and retain the old ARNs in `OAUTH_KMS_VERIFY_KEY_IDS` until every outstanding JWT has expired. The HTTP admin key-rotation endpoint intentionally refuses rotation in KMS mode; rotation is a controlled infrastructure rollout.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
pip-audit -r requirements.txt
```

GitHub Actions additionally runs PostgreSQL + Redis integration checks and a Docker Compose HTTP smoke test. Inspect the actual run status before promotion.

## Limits

Only **Client Credentials** is provided; Authorization Code + PKCE, refresh tokens, OpenID Connect user login, mTLS, and private-key JWT client auth are outside this implementation. Real administrator IdP provisioning, managed database/Redis, external alert routing, cloud IAM assignment, HA load balancing, backups, DNS, and production deployment require environment-specific setup and verification. A threat model and independent security review are recommended before public exposure.

Standards: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700).
