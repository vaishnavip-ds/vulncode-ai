# VulnCode AI

VulnCode AI is a GitHub-native security remediation platform. This repository contains the first production-shaped vertical slice: signed GitHub webhooks, idempotent scan creation, Semgrep ingestion, normalized findings, PostgreSQL persistence, and GitHub Check reporting.

## What works now

- Verifies GitHub webhook HMAC signatures before parsing events.
- Deduplicates webhook deliveries using `X-GitHub-Delivery`.
- Creates one scan per repository commit.
- Normalizes Semgrep results into CWE-aware findings.
- Stores data in SQLite for local development or PostgreSQL through Docker Compose.
- Publishes GitHub Check annotations when GitHub App credentials are configured.
- Runs the scanner in GitHub Actions so untrusted repository code does not execute in the API container.

Patch generation, deterministic validation, and draft pull-request creation are the next milestones.

## Local setup

Prerequisites: Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
export VULNCODE_ENVIRONMENT=development
export VULNCODE_WEBHOOK_SECRET='replace-this'
export VULNCODE_INGEST_TOKEN='replace-this-too'
export VULNCODE_API_TOKEN='replace-this-as-well'
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`, with interactive documentation at `/docs`.

Run checks:

```bash
ruff check .
pytest
```

## Docker setup

Create a `.env` file containing `VULNCODE_WEBHOOK_SECRET`, `VULNCODE_INGEST_TOKEN`, and `VULNCODE_API_TOKEN`, then run:

```bash
docker compose up --build
```

## GitHub App configuration

Create a private GitHub App for the organization or account used for the prototype.

Repository permissions:

- Metadata: read
- Contents: read
- Checks: write
- Pull requests: write only when draft PR delivery is implemented

Subscribe to the `push` event. Configure the webhook URL as:

```text
https://YOUR_PUBLIC_API/api/v1/webhooks/github
```

Set the same high-entropy webhook secret in GitHub and `VULNCODE_WEBHOOK_SECRET`. Set `VULNCODE_GITHUB_APP_ID` and the PEM private key in `VULNCODE_GITHUB_PRIVATE_KEY` to enable GitHub Check publishing.

## Repository workflow configuration

Copy `.github/workflows/vulncode-scan.yml` and `scripts/upload_semgrep.py` into a repository being scanned. Configure:

- Repository variable `VULNCODE_API_URL`
- Repository variable `VULNCODE_INSTALLATION_ID`
- Repository secret `VULNCODE_INGEST_TOKEN`

The workflow uses read-only repository permissions, runs Semgrep, uploads normalized findings, and preserves the raw Semgrep JSON as a workflow artifact.

## Security decisions

- The API does not clone or execute repository code.
- GitHub App tokens are generated only when needed and are not stored.
- Webhook and ingestion secrets are separate.
- Scan read APIs require a third, separate bearer token.
- Generated patches will never merge automatically.
- Validation will run in a separate sandbox without API or GitHub credentials.

See `docs/ARCHITECTURE.md` and `docs/PRODUCTION_READINESS.md` before expanding the prototype.
