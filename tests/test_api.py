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
async def test_health_webhook_and_ingestion_flow() -> None:
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
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
