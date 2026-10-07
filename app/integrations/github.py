from __future__ import annotations

import time
from typing import Any

import httpx
import jwt

from app.core.config import Settings
from app.db.models import Scan


class GitHubAppClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _app_jwt(self) -> str:
        if not self.settings.github_app_id or not self.settings.github_private_key:
            raise RuntimeError("GitHub App credentials are not configured")
        now = int(time.time())
        private_key = self.settings.github_private_key.replace("\\n", "\n")
        return jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": self.settings.github_app_id},
            private_key,
            algorithm="RS256",
        )

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": self.settings.github_api_version,
        }

    async def installation_token(self, installation_id: int) -> str:
        url = f"{self.settings.github_api_url}/app/installations/{installation_id}/access_tokens"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, headers=self._headers(self._app_jwt()))
            response.raise_for_status()
            return str(response.json()["token"])

    async def publish_scan_check(self, scan: Scan) -> None:
        if not scan.installation_id:
            raise RuntimeError("The scan has no GitHub App installation ID")
        token = await self.installation_token(scan.installation_id)
        owner, repository = scan.repository_full_name.split("/", 1)
        url = f"{self.settings.github_api_url}/repos/{owner}/{repository}/check-runs"
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in scan.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        blocking = counts["critical"] + counts["high"]
        conclusion = "failure" if blocking else "success"
        summary = (
            f"Found {len(scan.findings)} issue(s): "
            f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low."
        )
        annotations: list[dict[str, Any]] = []
        for finding in scan.findings[:50]:
            annotations.append(
                {
                    "path": finding.path,
                    "start_line": finding.start_line,
                    "end_line": finding.end_line,
                    "annotation_level": (
                        "failure" if finding.severity in {"critical", "high"} else "warning"
                    ),
                    "message": finding.message[:65000],
                    "title": f"{finding.rule_id} ({finding.cwe or 'CWE unavailable'})",
                }
            )
        payload = {
            "name": "VulnCode AI security scan",
            "head_sha": scan.commit_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": "VulnCode AI scan completed",
                "summary": summary,
                "annotations": annotations,
            },
        }
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, headers=self._headers(token), json=payload)
            response.raise_for_status()

