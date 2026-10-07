from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.dependencies import require_api_token
from app.core.config import Settings, get_settings
from app.core.security import verify_bearer_token
from app.db.models import Scan
from app.db.session import get_session
from app.integrations.github import GitHubAppClient
from app.schemas.scans import ScanResponse, SemgrepIngestRequest, SemgrepIngestResponse
from app.services.scans import create_or_update_scan, replace_findings
from app.services.semgrep import normalize_semgrep

router = APIRouter(prefix="/api/v1", tags=["scans"])
logger = logging.getLogger(__name__)


@router.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> list[Scan]:
    statement = select(Scan).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc())
    return list((await session.scalars(statement)).all())


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> Scan:
    statement = select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
    scan = await session.scalar(statement)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/ingest/semgrep", response_model=SemgrepIngestResponse)
async def ingest_semgrep(
    request: SemgrepIngestRequest,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> SemgrepIngestResponse:
    if not verify_bearer_token(authorization, settings.ingest_token):
        raise HTTPException(status_code=401, detail="Invalid ingestion token")

    normalized = normalize_semgrep(request.semgrep)
    scan = await create_or_update_scan(
        session,
        repository_full_name=request.repository_full_name,
        commit_sha=request.commit_sha,
        ref=request.ref,
        installation_id=request.installation_id,
        trigger="github_action",
    )
    scan = await replace_findings(session, scan, normalized)
    await session.commit()

    github_check = "not_configured"
    if settings.github_checks_enabled and scan.installation_id:
        try:
            await GitHubAppClient(settings).publish_scan_check(scan)
            github_check = "published"
        except Exception:
            logger.exception("Failed to publish GitHub Check for scan %s", scan.id)
            github_check = "failed"

    return SemgrepIngestResponse(
        scan=ScanResponse.model_validate(scan),
        normalized_findings=len(normalized),
        github_check=github_check,
    )
