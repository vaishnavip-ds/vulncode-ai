from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.dependencies import require_api_token
from app.core.config import Settings, get_settings
from app.db.models import Finding, Patch, PatchStatus
from app.db.session import get_session
from app.integrations.github import GitHubAppClient
from app.schemas.patches import (
    PatchDeliveryResponse,
    PatchGenerateRequest,
    PatchRejectRequest,
    PatchResponse,
    PatchValidationResponse,
    ValidationReportResponse,
)
from app.services.patches import UnsupportedRemediationError, build_patch, validate_patch

router = APIRouter(prefix="/api/v1/patches", tags=["patches"])


@router.get("", response_model=list[PatchResponse])
async def list_patches(
    finding_id: str | None = None,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> list[Patch]:
    statement = select(Patch).order_by(Patch.created_at.desc())
    if finding_id:
        statement = statement.where(Patch.finding_id == finding_id)
    return list((await session.scalars(statement)).all())


async def _load_patch(session: AsyncSession, patch_id: str) -> Patch:
    statement = (
        select(Patch)
        .where(Patch.id == patch_id)
        .options(selectinload(Patch.finding).selectinload(Finding.scan))
    )
    patch = await session.scalar(statement)
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    return patch


@router.post("/generate", response_model=PatchResponse, status_code=201)
async def generate_patch(
    request: PatchGenerateRequest,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> Patch:
    finding = await session.get(Finding, request.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        patch = build_patch(finding, request.source_content, request.placeholder_style)
    except UnsupportedRemediationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    session.add(patch)
    await session.commit()
    await session.refresh(patch)
    return patch


@router.get("/{patch_id}", response_model=PatchResponse)
async def get_patch(
    patch_id: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> Patch:
    return await _load_patch(session, patch_id)


@router.post("/{patch_id}/validate", response_model=PatchValidationResponse)
async def run_validation(
    patch_id: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> PatchValidationResponse:
    patch = await _load_patch(session, patch_id)
    report = validate_patch(patch)
    await session.commit()
    return PatchValidationResponse(
        patch=PatchResponse.model_validate(patch),
        validation=ValidationReportResponse.model_validate(report, from_attributes=True),
    )


@router.post("/{patch_id}/reject", response_model=PatchResponse)
async def reject_patch(
    patch_id: str,
    request: PatchRejectRequest,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_api_token),
) -> Patch:
    patch = await _load_patch(session, patch_id)
    if patch.status == PatchStatus.DELIVERED.value:
        raise HTTPException(status_code=409, detail="A delivered patch cannot be rejected")
    patch.status = PatchStatus.REJECTED.value
    patch.validation_json = json.dumps(
        {
            "passed": False,
            "checks": [
                {"name": "reviewer_decision", "passed": False, "detail": request.reason}
            ],
        },
        separators=(",", ":"),
    )
    await session.commit()
    await session.refresh(patch)
    return patch


@router.post("/{patch_id}/deliver", response_model=PatchDeliveryResponse)
async def deliver_patch(
    patch_id: str,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _: None = Depends(require_api_token),
) -> PatchDeliveryResponse:
    patch = await _load_patch(session, patch_id)
    if patch.status != PatchStatus.VALIDATED.value:
        raise HTTPException(status_code=409, detail="Only validated patches can be delivered")
    scan = patch.finding.scan
    if not settings.github_checks_enabled or not scan.installation_id:
        raise HTTPException(status_code=503, detail="GitHub App delivery is not configured")
    try:
        result = await GitHubAppClient(settings).create_remediation_pr(patch)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    patch.branch_name = result.branch_name
    patch.pr_url = result.pull_request_url
    patch.status = PatchStatus.DELIVERED.value
    await session.commit()
    return PatchDeliveryResponse(
        patch=PatchResponse.model_validate(patch), pull_request_url=result.pull_request_url
    )
