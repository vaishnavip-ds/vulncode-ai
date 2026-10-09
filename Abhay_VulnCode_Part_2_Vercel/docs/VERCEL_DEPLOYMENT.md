# Deploy VulnCode AI from GitHub to Vercel

This deployment contains only the GitHub App API. After deployment, the product is used through GitHub Checks and draft pull requests—not through a website.

## 1. Combine and push the contribution sets

Extract and upload the Vaishnavi set first. Extract and upload the Abhay set second. The combined repository must contain `vercel.json`, `pyproject.toml`, `app/`, `.github/`, `scripts/`, and `docs/` at its root.

## 2. Import the repository

1. In Vercel, select **Add New → Project**.
2. Import `vaishnavip-ds/vulncode-ai`.
3. Leave the root directory as `./`.
4. Vercel detects the FastAPI entrypoint from `pyproject.toml`.
5. Do not select a frontend framework or output directory.

## 3. Add PostgreSQL

Open the project **Storage** or **Marketplace** tab and add a Neon Postgres integration. Make the database variables available to Production and Preview.

VulnCode AI accepts `VULNCODE_DATABASE_URL`, `POSTGRES_URL`, or `DATABASE_URL`. Standard `postgres://` and `postgresql://` URLs are automatically converted to SQLAlchemy's asyncpg driver.

## 4. Configure environment variables

Create three independent secrets with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Add these Vercel environment variables:

```text
VULNCODE_ENVIRONMENT=development
VULNCODE_DATABASE_URL=<Neon pooled connection URL>
VULNCODE_WEBHOOK_SECRET=<secret 1>
VULNCODE_INGEST_TOKEN=<secret 2>
VULNCODE_API_TOKEN=<secret 3>
VULNCODE_GITHUB_APP_ID=
VULNCODE_GITHUB_PRIVATE_KEY=
VULNCODE_GITHUB_API_URL=https://api.github.com
VULNCODE_GITHUB_API_VERSION=2026-03-10
```

For the internal pilot, `development` creates the schema automatically. Before a public launch, introduce formal migrations and switch to `production`.

## 5. Deploy and verify

Deploy the project and open:

```text
https://YOUR_PROJECT.vercel.app/
https://YOUR_PROJECT.vercel.app/health
https://YOUR_PROJECT.vercel.app/docs
```

The root response should identify itself as `GitHub App API`, and `/health` should return `status: ok`.

## 6. Register the GitHub App

Follow `docs/GITHUB_APP_SETUP.md`, using:

```text
Webhook URL: https://YOUR_PROJECT.vercel.app/api/v1/webhooks/github
Webhook secret: the same VULNCODE_WEBHOOK_SECRET stored in Vercel
```

After GitHub creates the App, add its App ID and entire private key to the two empty Vercel variables, then redeploy.

## 7. Configure the repository workflow

In **GitHub repository → Settings → Secrets and variables → Actions**, add:

Variables:

```text
VULNCODE_API_URL=https://YOUR_PROJECT.vercel.app
VULNCODE_INSTALLATION_ID=<GitHub App installation ID>
```

Secret:

```text
VULNCODE_INGEST_TOKEN=<same value stored in Vercel>
```

Push a commit and inspect **Checks → VulnCode AI security scan**.

## Internal-pilot limitation

The **Create safe fixes** action currently runs as a FastAPI background task and remains bounded by Vercel Function duration. The included `vercel.json` requests a five-minute maximum. Before real-scale launch, move remediation to Vercel Queues, Workflow, or another durable worker queue.
