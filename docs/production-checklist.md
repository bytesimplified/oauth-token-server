# Production deployment checklist

This document is a checklist, not evidence of a completed production deployment.

- [ ] Use HTTPS at the ingress and configure the public issuer URL.
- [ ] Restrict admin, metrics, database, and Redis network access.
- [ ] Connect a real administrator OIDC identity provider with RBAC and MFA.
- [ ] Replace filesystem signing-key storage with centralized KMS/HSM for multiple replicas.
- [ ] Store secrets in a secret manager and implement rotation.
- [ ] Deploy managed PostgreSQL with backups, restore testing, and schema migrations.
- [ ] Deploy managed Redis with monitoring; test limiter fail-closed behavior.
- [ ] Run the entire test suite, dependency audit, Docker build, and integration tests against PostgreSQL/Redis.
- [ ] Test key rollover and token verification across replicas.
- [ ] Configure Prometheus collection for /internal/metrics with a protected key.
- [ ] Set alert rules for error spikes, denied token requests, and service unavailability.
- [ ] Define audit retention, access restrictions, and data minimization.
- [ ] Test revocation propagation and multi-audience authorization boundaries.
- [ ] Perform a threat model, penetration test, and security review before internet exposure.
