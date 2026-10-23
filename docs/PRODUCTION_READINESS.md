# Production-readiness gates

## Required before an internal pilot

- Replace development defaults with secrets from a managed secret store.
- Add database migrations and disable automatic schema creation outside development.
- Put asynchronous work on a durable queue with retries and dead-letter handling.
- Rate-limit webhook and ingestion endpoints.
- Replace the shared ingestion token with GitHub OIDC or short-lived, repository-scoped credentials.
- Run compiler and test validation in ephemeral sandboxes without service credentials.
- Encrypt stored repository metadata and define retention rules.
- Add structured logs, request IDs, metrics, and alerts.
- Add an explicit repository allowlist and per-installation authorization checks.
- Complete threat modeling for prompt injection, malicious build scripts, dependency attacks, and token theft.
- Add an append-only audit event table for reviewer, validation, and delivery actions.
- Pin base container images by digest and add SBOM/dependency scanning in CI.

## Required before a public launch

- Add tenant isolation and organization administration.
- Add model and policy version pinning with rollback.
- Add abuse controls, quotas, and cost limits.
- Complete privacy, terms, deletion, incident-response, and vulnerability-disclosure processes.
- Perform an external penetration test and dependency/container security review.
- Publish measurable benchmark results instead of treating project targets as achieved outcomes.
- Add regional data controls, tenant-scoped encryption keys, SSO/SCIM, and role-based authorization.

## Current prototype limitations

- Patch generation supports two deliberately narrow patterns; this is a safety boundary, not broad AI coverage.
- Validation parses Python but does not yet run repository tests in an isolated worker.
- GitHub requested-action work currently uses an in-process background task rather than a durable worker queue.
- Schema creation is automatic only in development/test; formal Alembic migrations are still required.
- GitHub is the only delivery adapter.
