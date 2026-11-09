# Production deployment guide

The implementation supports AWS KMS, AWS Secrets Manager, Redis, PostgreSQL, OIDC admin auth, and HTTPS via Caddy. **It does not create live cloud infrastructure without your account, identity provider, domain and DNS.** This guide describes required operations for an AWS-hosted workload.

## 1. Choose your runtime and IAM role

Run the API with an IAM **workload role** (e.g. ECS task role, EKS IRSA/pod identity, or EC2 instance role). Never embed IAM access keys in environment files. Restrict API, metrics, and administration to permitted networks; put TLS at the edge.

In `infra/aws`, run `terraform init` and `terraform apply -var aws_region=us-east-1 -var workload_role_name=YOUR_EXISTING_ROLE`. The Terraform provisions an RSA-3072 KMS signing key, a Secrets Manager secret *container*, and the runtime IAM role policy. It does **not** put any secret **value** into Terraform state. The outputs provide key and secret ARNs. Set `OAUTH_KMS_KEY_ID` and `OAUTH_AWS_SECRET_ARN` to those **immutable** ARNs.

Before changing production infrastructure, review `terraform plan` and use a remote encrypted Terraform state with access controls.

## 2. Populate the runtime secret securely

Store a JSON object as the Secrets Manager secret **value**:

```json
{
  "OAUTH_DB_URL": "postgresql+psycopg://oauth:<url-encoded-password>@db.example.com:5432/oauth?sslmode=require",
  "OAUTH_REDIS_URL": "rediss://redis.example.com:6379/0",
  "OAUTH_METRICS_KEY": "<random-strong-secret>"
}
```

Use the AWS console, an approved secret-delivery pipeline, or an AWS CLI command that reads from a protected local file. Avoid command-line literal passwords, shell-history leakage, and plaintext secret values in Terraform state. This service reads the secret **once per process startup** and applies its approved keys to environment settings. **Restart tasks after any secret rotation.** Enable AWS Secrets Manager rotation according to your database/Redis capabilities.

## 3. Administrator identities and roles

Configure an actual OIDC identity provider to issue RS256-signed admin access tokens with a dedicated audience and `roles` claim. Set:

```text
OAUTH_ADMIN_OIDC_ISSUER=https://your-idp.example.com
OAUTH_ADMIN_OIDC_AUDIENCE=oauth-admin
OAUTH_ADMIN_OIDC_JWKS_URL=https://your-idp.example.com/.well-known/jwks.json
OAUTH_ADMIN_ROLE_CLAIM=roles
```

A token must contain `admin` for write endpoints or `viewer` (or `admin`) for read endpoints. Configure MFA, session controls, and access reviews in your IdP; none are provisioned by this repository. The `/admin/ui` key-entry interface is disabled in production.

## 4. TLS and reverse proxy

Set DNS A/AAAA records for your OAuth domain and allow ACME verification and HTTPS (ports 80/443). Copy `.env.production.example` to `.env.production`, configure public HTTPS issuer, AWS resource ARNs, and OIDC. Start:

```bash
docker compose --env-file .env.production -f deploy/compose.production.yaml up -d --build
```

The sample deploys Caddy with automatic HTTPS and an unexposed HTTP FastAPI backend. Only the Caddy container exposes ports. Configure inbound firewall restrictions and monitor certificate renewal. This is **single-host reference infrastructure**, not multi-zone highly available production orchestration. In production use managed ingress and managed Postgres/Redis with TLS as appropriate.

## 5. Key rotation without losing verification

AWS KMS cannot automatically rotate asymmetric keys as an equivalent transparent key version. Use this controlled process:

1. Provision a **new** asymmetric RSA SIGN_VERIFY KMS key, grant the workload `kms:Sign` and `kms:GetPublicKey` for the new key. Retain `kms:GetPublicKey` on old keys.
2. Add the old immutable key ARN(s) to `OAUTH_KMS_VERIFY_KEY_IDS` and set `OAUTH_KMS_KEY_ID` to the new key ARN. Roll out to **all** instances.
3. Verify `/.well-known/jwks.json` contains public keys for active and retired key IDs, validate old and new tokens on each instance.
4. Wait longer than the maximum token lifetime plus clock/cache skew before removing retired keys and IAM verification rights.

Never set the HTTP admin rotate endpoint as an automated production key-rotation job. KMS keeps the private material non-exportable.

## 6. Monitoring, alerts and operational cleanup

Prometheus uses `GET /internal/metrics` with `X-Metrics-Key`. Configure `monitoring/prometheus.example.yml` and `monitoring/alerts.yml` with your domain and a protected Prometheus header file. Connect an Alertmanager receiver (email, PagerDuty or other approved channel) separately. Configure TLS and restrict access to the metrics endpoint.

A read-only admin `GET /admin/analytics?hours=24` aggregates per-client hourly token issuances and denials from audit events. For database retention:

```bash
python -m app.retention --audit-retention-days 90
```

Schedule this periodically using your orchestration system; the application does **not** schedule cron jobs by itself.

## 7. Encrypted backups and verified restoration

Use `pg_dump` and `pg_restore` versions matching the server major version to avoid incompatible archive commands and settings. Test restores on an equal-or-newer server. Install PostgreSQL client tooling and [age](https://github.com/FiloSottile/age). Configure `PGHOST`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` through your secure deployment system and an `AGE_RECIPIENT` public key, then run `scripts/backup_postgres.sh /secure/path/oauth-backup.dump.age`. It streams pg_dump custom format through age encryption without writing unencrypted files. Store encrypted backups off-host with retention, access control, and immutable copies.

Test restore into an **isolated staging database** using `CONFIRM_RESTORE=YES AGE_IDENTITY_FILE=/secure/key.txt scripts/restore_postgres.sh /secure/path/oauth-backup.dump.age`. A failed restore must block promotion. Rehearse recovery regularly; back up related configuration and KMS key policies separately.

## 8. Validation before go-live

Run CI and confirm both unit tests and the PostgreSQL/Redis/Docker integration jobs pass. Validate readiness `GET /health/ready`, OAuth issuance/introspection/revocation, rate-limit rejection, resource audience boundaries, KMS sign/verify across multiple instances, expired token denial, TLS, IdP permissions, alert delivery, backup restore, and the incident runbook. Commission an independent security review for externally exposed OAuth services.
