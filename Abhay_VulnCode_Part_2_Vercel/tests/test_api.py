from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


def signature(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@pytest.mark.asyncio
async def test_health_webhook_and_ingestion_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            root = await client.get("/")
            assert root.status_code == 200
            assert root.json()["type"] == "GitHub App API"

            health = await client.get("/health")
            assert health.json()["status"] == "ok"

            delivery_id = str(uuid.uuid4())
            ping_body = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
            headers = {
                "X-GitHub-Event": "ping",
                "X-GitHub-Delivery": delivery_id,
                "X-Hub-Signature-256": signature(
                    ping_body, "development-webhook-secret-change-me"
                ),
                "Content-Type": "application/json",
            }
            response = await client.post(
                "/api/v1/webhooks/github", content=ping_body, headers=headers
            )
            assert response.status_code == 202
            assert response.json()["status"] == "pong"

            duplicate = await client.post(
                "/api/v1/webhooks/github", content=ping_body, headers=headers
            )
            assert duplicate.status_code == 202
            assert duplicate.json()["status"] == "duplicate"

            ingest = await client.post(
                "/api/v1/ingest/semgrep",
                headers={"Authorization": "Bearer development-ingest-token-change-me"},
                json={
                    "repository_full_name": "vulncode/demo",
                    "commit_sha": "a" * 40,
                    "ref": "refs/heads/main",
                    "installation_id": 123,
                    "semgrep": {
                        "results": [
                            {
                                "check_id": "python.sql-injection",
                                "path": "app.py",
                                "start": {"line": 5},
                                "end": {"line": 5},
                                "extra": {
                                    "message": "Possible SQL injection",
                                    "severity": "ERROR",
                                    "metadata": {
                                        "cwe": "CWE-89",
                                        "confidence": "HIGH",
                                    },
                                },
                            }
                        ]
                    },
                },
            )
            assert ingest.status_code == 200
            result = ingest.json()
            assert result["normalized_findings"] == 1
            assert result["scan"]["status"] == "completed"
            assert result["scan"]["findings"][0]["cwe"] == "CWE-89"

            remediation_calls: list[str] = []

            async def fake_remediate_scan(scan_id: str, _settings: object) -> None:
                remediation_calls.append(scan_id)

            monkeypatch.setattr("app.api.webhooks.remediate_scan", fake_remediate_scan)
            action_body = json.dumps(
                {
                    "action": "requested_action",
                    "requested_action": {"identifier": "create_safe_fixes"},
                    "check_run": {"external_id": result["scan"]["id"]},
                    "installation": {"id": 123},
                }
            ).encode("utf-8")
            action_response = await client.post(
                "/api/v1/webhooks/github",
                content=action_body,
                headers={
                    "X-GitHub-Event": "check_run",
                    "X-GitHub-Delivery": str(uuid.uuid4()),
                    "X-Hub-Signature-256": signature(
                        action_body, "development-webhook-secret-change-me"
                    ),
                    "Content-Type": "application/json",
                },
            )
            assert action_response.status_code == 202
            assert action_response.json()["status"] == "remediation_queued"
            assert remediation_calls == [result["scan"]["id"]]

            finding_id = result["scan"]["findings"][0]["id"]
            generated = await client.post(
                "/api/v1/patches/generate",
                headers={"Authorization": "Bearer development-api-token-change-me"},
                json={
                    "finding_id": finding_id,
                    "source_content": (
                        "def lookup(cursor, username):\n"
                        '    cursor.execute(f"SELECT * FROM users WHERE username = '
                        "'{username}'\")\n"
                    ),
                },
            )
            assert generated.status_code == 201
            patch_id = generated.json()["id"]
            validated = await client.post(
                f"/api/v1/patches/{patch_id}/validate",
                headers={"Authorization": "Bearer development-api-token-change-me"},
            )
            assert validated.status_code == 200
            assert validated.json()["validation"]["passed"] is True

            listed = await client.get(
                f"/api/v1/patches?finding_id={finding_id}",
                headers={"Authorization": "Bearer development-api-token-change-me"},
            )
            assert listed.status_code == 200
            assert listed.json()[0]["id"] == patch_id

            rejected = await client.post(
                f"/api/v1/patches/{patch_id}/reject",
                headers={"Authorization": "Bearer development-api-token-change-me"},
                json={"reason": "The repository uses a different SQL placeholder style."},
            )
            assert rejected.status_code == 200
            assert rejected.json()["status"] == "rejected"
