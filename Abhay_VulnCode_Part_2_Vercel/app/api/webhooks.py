from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security import verify_github_signature
from app.db.models import Scan, WebhookDelivery
from app.db.session import get_session
from app.services.remediation import remediate_scan
from app.services.scans import create_or_update_scan

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
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

    if x_github_event == "check_run" and payload.get("action") == "requested_action":
        requested_action = (payload.get("requested_action") or {}).get("identifier")
        scan_id = (payload.get("check_run") or {}).get("external_id")
        if requested_action != "create_safe_fixes" or not scan_id:
            await session.commit()
            return {"status": "ignored", "delivery_id": x_github_delivery}
        scan = await session.scalar(select(Scan).where(Scan.id == scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan for check run was not found")
        installation_id = (payload.get("installation") or {}).get("id")
        if installation_id and scan.installation_id != installation_id:
            raise HTTPException(status_code=403, detail="Installation does not own this scan")
        await session.commit()
        background_tasks.add_task(remediate_scan, scan.id, settings)
        return {"status": "remediation_queued", "delivery_id": x_github_delivery}

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
