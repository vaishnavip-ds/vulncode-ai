# VulnCode AI architecture

## Current vertical slice

1. GitHub sends a signed `push` webhook.
2. The API validates `X-Hub-Signature-256` before parsing the payload.
3. The delivery ID is persisted to make webhook processing idempotent.
4. A scan is created for the repository and commit.
5. GitHub Actions checks out the commit and runs Semgrep on an isolated runner.
6. The workflow sends Semgrep JSON to the authenticated ingestion endpoint.
7. The backend normalizes findings and stores their CWE, severity, confidence, and location.
8. When GitHub App credentials are configured, the backend publishes a GitHub Check with inline annotations.

## Planned service boundaries

- **Scanner adapter:** Semgrep today; additional SAST engines can implement the same normalized finding contract.
- **Scoring service:** AST-aware classifier enriches normalized findings without changing webhook or API code.
- **Patch generator:** consumes a finding plus repository context and returns a unified diff with model provenance.
- **Validator:** executes AST parsing, compilation, and tests in a disposable sandbox.
- **Delivery adapter:** starts with GitHub Checks, then creates draft remediation pull requests.
- **Audit store:** records model version, context hash, validation evidence, and delivery state.

## Scale path

The current API performs lightweight database operations inline. Before a multi-repository pilot, move scan, model, and validation work to a durable queue. API replicas should remain stateless. Run model inference and untrusted validation in separate worker pools. Never place GitHub App private keys or production tokens in validation containers.

