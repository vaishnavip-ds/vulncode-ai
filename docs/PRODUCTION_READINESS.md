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

## Required before a public launch

- Add tenant isolation and organization administration.
- Add model and policy version pinning with rollback.
- Add abuse controls, quotas, and cost limits.
- Complete privacy, terms, deletion, incident-response, and vulnerability-disclosure processes.
- Perform an external penetration test and dependency/container security review.
- Publish measurable benchmark results instead of treating project targets as achieved outcomes.

