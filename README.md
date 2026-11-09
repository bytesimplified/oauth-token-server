# OAuth 2.0 Client Credentials Token Server

A working **machine-to-machine OAuth 2.0 Authorization Server** and example protected API, built with FastAPI. This is a reference implementation, not a turnkey hardened identity platform.

## Architecture

```text
Client app -- client_id + client_secret --> POST /oauth/token
                       |
                Validate against hashed client secret in database
                       |
                Validate requested scopes
                       |
                Sign RS256 JWT (private key)
                       |
Client app <-- Bearer access token
                       |
Client app -- Authorization: Bearer <JWT> --> GET /api/orders
                Verify signature, issuer, audience, expiry, scopes
```

Only the **Client Credentials** grant and **HTTP Basic client authentication** are implemented. There is no user login, consent screen, authorization-code grant, or refresh token. Client registration uses a local admin CLI rather than public HTTP registration.

## Quick start (Python 3.11+)

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m app.cli generate-keys
python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Save the resulting client ID and secret securely. The CLI displays the secret only once. The database stores the client ID, salted scrypt hash of the secret, scopes, and active status. The RSA private key is stored separately at `./keys/private.pem` by default; do not commit it. Configuration uses `OAUTH_*` environment variables listed in `.env.example`. The example file is not loaded automatically.

## Docker Compose (local development)

```bash
mkdir -p data keys
docker compose build
docker compose run --rm oauth python -m app.cli generate-keys
docker compose run --rm oauth python -m app.cli create-client --scopes orders:read orders:write --default-scopes orders:read
docker compose up
```

Compose binds plain HTTP to localhost only. For external access, deploy behind correctly configured HTTPS.

## Token request

```bash
curl -sS -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&scope=orders%3Aread' \
  http://127.0.0.1:8000/oauth/token
```

Example response (token shortened):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "orders:read"
}
```

To access the protected API:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/orders
```

The token endpoint requires URL-encoded form data (not JSON). `grant_type=client_credentials` is required; `scope` is optional and must be a subset of the client's allowed scopes.

## Endpoints

| Route | Method | Purpose |
| --- | --- | --- |
| `/oauth/token` | POST | Issue RS256 JWT access tokens |
| `/.well-known/oauth-authorization-server` | GET | OAuth authorization server metadata |
| `/.well-known/jwks.json` | GET | RSA public verification key |
| `/api/orders` | GET | Example API requiring `orders:read` |

JWTs include `iss`, `sub`, `aud`, `client_id`, `scope`, `iat`, `nbf`, `exp`, and `jti`, with `typ=at+jwt`. The signing key is not shared with clients. The single configured audience comes from `OAUTH_AUDIENCE`.

Invalid client credentials return HTTP 401 with `invalid_client`; unsupported grants or scopes return HTTP 400. Protected APIs return HTTP 401 for invalid or expired tokens and HTTP 403 for insufficient scope.

## Administration

```bash
python -m app.cli list-clients
python -m app.cli rotate-client-secret cli_...
python -m app.cli deactivate-client cli_...
```

Rotation invalidates the old **client secret** for new token issuance. Deactivation blocks new issuance. Existing short-lived JWTs remain valid until expiration. For instant revocation, introduce introspection or a token denylist.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The test suite covers the token flow, authentication errors, permissions, JWKS verification, token tampering, audience/expiry rejection, and secret rotation.

## Before production

1. Use HTTPS and set `OAUTH_ISSUER` to the exact external HTTPS URL.
2. Move to PostgreSQL with schema migrations and backups.
3. Store signing keys in KMS/HSM or a controlled secret manager; implement key rotation with overlapping JWKS keys.
4. Add distributed rate limiting, audit trails, monitoring, request size limits, and secure proxy configuration.
5. Never log client secrets or access tokens. Keep credentials and databases out of version control.
6. Consider mTLS or private-key JWT authentication for high-assurance clients.
7. For multiple APIs, implement RFC 8707 resource indicators and appropriate client-resource authorization.
8. For mission-critical authentication, evaluate a mature maintained authorization server.

## Standards

- [RFC 6749 §4.4 — Client Credentials](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
- [RFC 9068 — JWT Access Token Profile](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9700 — OAuth Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 8414 — OAuth Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
