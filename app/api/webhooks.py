from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security import verify_github_signature
from app.db.models import WebhookDelivery
from app.db.session import get_session
from app.services.scans import create_or_update_scan

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    x_github_event: str = Header(alias="X-GitHub-Event"),
    x_github_delivery: str = Header(alias="X-GitHub-Delivery"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    raw_body = await request.body()
    if not verify_github_signature(raw_body, x_hub_signature_256, settings.webhook_secret):
        raise HTTPException(status_code=403, detail="Invalid GitHub webhook signature")

    session.add(WebhookDelivery(delivery_id=x_github_delivery, event=x_github_event))
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        return {"status": "duplicate", "delivery_id": x_github_delivery}

    payload = json.loads(raw_body)
    if x_github_event == "ping":
        await session.commit()
        return {"status": "pong", "delivery_id": x_github_delivery}

    if x_github_event != "push":
        await session.commit()
        return {"status": "ignored", "delivery_id": x_github_delivery}

    repository = (payload.get("repository") or {}).get("full_name")
    commit_sha = payload.get("after")
    if not repository or not commit_sha:
        raise HTTPException(status_code=400, detail="Push payload lacks repository or commit SHA")

    installation_id = (payload.get("installation") or {}).get("id")
    scan = await create_or_update_scan(
        session,
        repository_full_name=repository,
        commit_sha=commit_sha,
        ref=payload.get("ref"),
        installation_id=installation_id,
        trigger="github_push",
    )
    await session.commit()
    return {"status": "queued", "delivery_id": x_github_delivery, "scan_id": scan.id}

