# VulnCode AI — GitHub App

VulnCode AI is a GitHub-native security extension implemented as a **GitHub App**. It scans repositories with Semgrep, publishes inline GitHub Check annotations, and exposes a **Create safe fixes** action directly inside GitHub. That action generates conservative patches, validates them, and opens draft pull requests for human review. It never merges automatically.

There is no website or Chrome extension in this deliverable. The product interface is GitHub Checks and GitHub pull requests.

## GitHub experience

1. A push or pull request runs the VulnCode AI workflow.
2. Findings appear in **Checks → VulnCode AI security scan** and as annotations on affected lines.
3. For supported findings, the check includes a **Create safe fixes** button.
4. Clicking the button sends a signed `check_run.requested_action` webhook.
5. The App retrieves the exact file at the scanned commit, rejects stale content, validates a narrow patch, and opens a draft PR.
6. Developers review, test, and approve the PR through normal GitHub controls.

## Implemented capabilities

- Signed webhook verification and delivery deduplication
- Semgrep ingestion and CWE normalization
- PostgreSQL persistence with SQLite development mode
- GitHub Check summaries and inline annotations
- Native GitHub Check requested-action button
- Safe fixes for narrow Python SQL-injection and DOM-XSS patterns
- Deterministic syntax, bounded-diff, and dangerous-primitive validation
- Source-content verification before branch creation
- Draft remediation branches and pull requests
- No automatic merge

## Run locally

Prerequisites: Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
mkdir -p data
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`; API documentation is at `/docs`.

Run checks:

```bash
ruff check .
pytest
```

## Run with Docker

```bash
cp .env.example .env
# Replace every development secret.
docker compose up --build
```

## Deploy from GitHub to Vercel

The repository includes `vercel.json`, `.python-version`, and a configured FastAPI entrypoint. Import the completed GitHub repository into Vercel, connect a Neon PostgreSQL database, and add the required environment variables. Follow [Vercel deployment](docs/VERCEL_DEPLOYMENT.md) before registering the GitHub App webhook.

## Install the GitHub extension

Follow [GitHub App setup](docs/GITHUB_APP_SETUP.md). The reference permission/event configuration is in [the App manifest](.github/github-app-manifest.example.json).

Required repository permissions:

- Metadata: read
- Contents: read and write
- Checks: read and write
- Pull requests: read and write

Required events:

- Push
- Check run

## Safety and scale

The generator intentionally refuses unsupported patterns. Before a public launch, move remediation jobs to a durable queue, run repository tests in isolated workers, add formal database migrations, tenant authorization, audit events, rate limiting, and managed secrets. See [Architecture](docs/ARCHITECTURE.md) and [Production readiness](docs/PRODUCTION_READINESS.md).
