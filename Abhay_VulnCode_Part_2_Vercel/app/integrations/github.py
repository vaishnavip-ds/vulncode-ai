from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
import jwt

from app.core.config import Settings
from app.db.models import Patch, Scan
from app.services.patches import supports_finding


@dataclass(frozen=True, slots=True)
class PullRequestResult:
    branch_name: str
    pull_request_url: str


def build_scan_check_payload(scan: Scan) -> dict[str, Any]:
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
    payload: dict[str, Any] = {
        "name": "VulnCode AI security scan",
        "head_sha": scan.commit_sha,
        "external_id": scan.id,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "VulnCode AI scan completed",
            "summary": summary,
            "annotations": annotations,
        },
    }
    if any(supports_finding(finding) for finding in scan.findings):
        payload["actions"] = [
            {
                "label": "Create safe fixes",
                "description": "Generate validated fixes as draft pull requests",
                "identifier": "create_safe_fixes",
            }
        ]
    return payload


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
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                url,
                headers=self._headers(token),
                json=build_scan_check_payload(scan),
            )
            response.raise_for_status()

    async def get_file_content(self, scan: Scan, path: str) -> str:
        if not scan.installation_id:
            raise ValueError("The scan has no GitHub App installation ID")
        token = await self.installation_token(scan.installation_id)
        owner, repository = scan.repository_full_name.split("/", 1)
        encoded_path = quote(path, safe="/")
        url = (
            f"{self.settings.github_api_url}/repos/{owner}/{repository}/contents/{encoded_path}"
        )
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                url,
                headers=self._headers(token),
                params={"ref": scan.commit_sha},
            )
            response.raise_for_status()
        data = response.json()
        if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            raise ValueError("GitHub did not return base64 file content")
        return base64.b64decode(data["content"]).decode("utf-8")

    async def create_remediation_pr(self, patch: Patch) -> PullRequestResult:
        finding = patch.finding
        scan = finding.scan
        if not scan.installation_id:
            raise ValueError("The scan has no GitHub App installation ID")
        token = await self.installation_token(scan.installation_id)
        owner, repository = scan.repository_full_name.split("/", 1)
        repository_url = f"{self.settings.github_api_url}/repos/{owner}/{repository}"
        branch_name = f"vulncode/fix-{finding.id[:8]}-{patch.id[:8]}"
        encoded_path = quote(finding.path, safe="/")

        async with httpx.AsyncClient(timeout=30) as client:
            headers = self._headers(token)
            content_response = await client.get(
                f"{repository_url}/contents/{encoded_path}",
                headers=headers,
                params={"ref": scan.commit_sha},
            )
            content_response.raise_for_status()
            content_data = content_response.json()
            if content_data.get("encoding") != "base64":
                raise ValueError("GitHub did not return base64 file content")
            current_content = base64.b64decode(content_data["content"]).decode("utf-8")
            if current_content != patch.original_content:
                raise ValueError(
                    "Repository content changed or does not match the content used to "
                    "generate the patch"
                )

            reference_response = await client.post(
                f"{repository_url}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": scan.commit_sha},
            )
            reference_response.raise_for_status()

            update_response = await client.put(
                f"{repository_url}/contents/{encoded_path}",
                headers=headers,
                json={
                    "message": f"fix: remediate {finding.cwe or finding.rule_id}",
                    "content": base64.b64encode(patch.patched_content.encode("utf-8")).decode(
                        "ascii"
                    ),
                    "sha": content_data["sha"],
                    "branch": branch_name,
                },
            )
            update_response.raise_for_status()

            base_branch = (
                scan.ref.removeprefix("refs/heads/")
                if scan.ref and scan.ref.startswith("refs/heads/")
                else "main"
            )
            pull_response = await client.post(
                f"{repository_url}/pulls",
                headers=headers,
                json={
                    "title": f"VulnCode AI: remediate {finding.cwe or finding.rule_id}",
                    "body": self._pull_request_body(patch),
                    "head": branch_name,
                    "base": base_branch,
                    "draft": True,
                    "maintainer_can_modify": True,
                },
            )
            pull_response.raise_for_status()
            return PullRequestResult(
                branch_name=branch_name,
                pull_request_url=str(pull_response.json()["html_url"]),
            )

    def _pull_request_body(self, patch: Patch) -> str:
        finding = patch.finding
        return "\n".join(
            [
                "## VulnCode AI remediation",
                "",
                f"- Finding: `{finding.rule_id}`",
                f"- CWE: `{finding.cwe or 'unmapped'}`",
                f"- Severity: `{finding.severity}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Generator: `{patch.generator}`",
                "",
                "### Rationale",
                "",
                patch.rationale,
                "",
                "### Validation",
                "",
                "Deterministic validation passed before delivery. Review and run the repository's "
                "complete test suite before merging.",
                "",
                "This pull request is intentionally a draft. VulnCode AI never merges "
                "automatically.",
            ]
        )

