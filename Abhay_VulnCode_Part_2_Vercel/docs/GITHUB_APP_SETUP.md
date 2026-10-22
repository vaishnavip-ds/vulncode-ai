# Install VulnCode AI as a GitHub App

VulnCode AI is a GitHub App, not a browser page. Its interface appears in GitHub's **Checks**, code annotations, and **Pull requests**.

## 1. Deploy the API

Deploy the FastAPI container at a public HTTPS address. Configure PostgreSQL and the three secrets from `.env.example`. The webhook endpoint will be:

```text
https://YOUR_PUBLIC_API/api/v1/webhooks/github
```

For local development, expose port 8000 with a trusted HTTPS tunnel. Never publish a tunnel that uses the development secrets.

## 2. Register the GitHub App

Open GitHub **Settings → Developer settings → GitHub Apps → New GitHub App** and use:

- Name: `VulnCode AI` (or a unique development name)
- Homepage: the project repository URL
- Webhook URL: the public webhook endpoint above
- Webhook secret: the value of `VULNCODE_WEBHOOK_SECRET`
- Active: enabled

Repository permissions:

- Metadata: Read-only
- Contents: Read and write
- Checks: Read and write
- Pull requests: Read and write

Subscribe to:

- Push
- Check run

The reference configuration is in `.github/github-app-manifest.example.json`.

## 3. Configure the service

Generate a private key on the GitHub App settings page and configure:

```text
VULNCODE_GITHUB_APP_ID=<app id>
VULNCODE_GITHUB_PRIVATE_KEY=<complete PEM value>
```

Install the App on the test repository. Use **Only select repositories** for the internal pilot.

## 4. Add the scanning workflow

Copy `.github/workflows/vulncode-scan.yml` and `scripts/upload_semgrep.py` into the repository being protected. Configure:

- Variable `VULNCODE_API_URL`
- Variable `VULNCODE_INSTALLATION_ID`
- Secret `VULNCODE_INGEST_TOKEN`

## 5. Use the extension in GitHub

1. Push vulnerable code or open a pull request.
2. Open the commit or pull request **Checks** tab.
3. Open **VulnCode AI security scan** to see inline findings.
4. Click **Create safe fixes**.
5. VulnCode AI retrieves the exact scanned file, generates only supported fixes, validates the diff, and opens draft pull requests.
6. Review tests and code in GitHub, then mark the PR ready or close it. VulnCode AI never merges automatically.

The action is idempotent: findings that already have validated or delivered patches are skipped.
