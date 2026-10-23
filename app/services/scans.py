from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import Finding, Scan, ScanStatus
from app.services.semgrep import NormalizedFinding


async def get_scan_by_repo_commit(
    session: AsyncSession, repository_full_name: str, commit_sha: str
) -> Scan | None:
    statement = (
        select(Scan)
        .where(
            Scan.repository_full_name == repository_full_name,
            Scan.commit_sha == commit_sha,
        )
        .options(selectinload(Scan.findings))
    )
    return await session.scalar(statement)


async def create_or_update_scan(
    session: AsyncSession,
    *,
    repository_full_name: str,
    commit_sha: str,
    ref: str | None,
    installation_id: int | None,
    trigger: str,
) -> Scan:
    scan = await get_scan_by_repo_commit(session, repository_full_name, commit_sha)
    if scan:
        if installation_id:
            scan.installation_id = installation_id
        if ref:
            scan.ref = ref
        return scan
    scan = Scan(
        repository_full_name=repository_full_name,
        commit_sha=commit_sha,
        ref=ref,
        installation_id=installation_id,
        trigger=trigger,
        status=ScanStatus.QUEUED.value,
    )
    try:
        async with session.begin_nested():
            session.add(scan)
            await session.flush()
        return scan
    except IntegrityError:
        existing = await get_scan_by_repo_commit(session, repository_full_name, commit_sha)
        if not existing:
            raise
        if installation_id:
            existing.installation_id = installation_id
        if ref:
            existing.ref = ref
        return existing


async def replace_findings(
    session: AsyncSession, scan: Scan, findings: list[NormalizedFinding]
) -> Scan:
    scan.status = ScanStatus.RUNNING.value
    await session.execute(delete(Finding).where(Finding.scan_id == scan.id))
    for item in findings:
        session.add(
            Finding(
                scan_id=scan.id,
                fingerprint=item.fingerprint,
                rule_id=item.rule_id,
                cwe=item.cwe,
                severity=item.severity,
                confidence=item.confidence,
                path=item.path,
                start_line=item.start_line,
                end_line=item.end_line,
                message=item.message,
                evidence_json=item.evidence_json,
            )
        )
    scan.status = ScanStatus.COMPLETED.value
    await session.flush()
    await session.refresh(scan, attribute_names=["findings"])
    return scan
