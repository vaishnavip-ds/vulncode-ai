from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.db.models import Finding, Patch, PatchStatus, Scan
from app.db.session import SessionFactory
from app.integrations.github import GitHubAppClient
from app.services.patches import (
    UnsupportedRemediationError,
    build_patch,
    supports_finding,
    validate_patch,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RemediationSummary:
    delivered: int
    skipped: int
    failed: int


async def remediate_scan(scan_id: str, settings: Settings) -> RemediationSummary:
    """Generate validated draft PRs after a GitHub Check requested action."""
    delivered = 0
    skipped = 0
    failed = 0

    async with SessionFactory() as session:
        statement = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.findings).selectinload(Finding.patches))
        )
        scan = await session.scalar(statement)
        if not scan:
            logger.warning("Cannot remediate missing scan %s", scan_id)
            return RemediationSummary(0, 0, 1)
        if not scan.installation_id:
            logger.warning("Cannot remediate scan %s without an installation ID", scan_id)
            return RemediationSummary(0, 0, 1)

        github = GitHubAppClient(settings)
        for finding in scan.findings:
            if not supports_finding(finding):
                skipped += 1
                continue
            if any(
                patch.status in {PatchStatus.VALIDATED.value, PatchStatus.DELIVERED.value}
                for patch in finding.patches
            ):
                skipped += 1
                continue
            try:
                source = await github.get_file_content(scan, finding.path)
                patch: Patch = build_patch(finding, source)
                patch.finding = finding
                report = validate_patch(patch)
                session.add(patch)
                await session.commit()
                if not report.passed:
                    skipped += 1
                    continue

                result = await github.create_remediation_pr(patch)
                patch.branch_name = result.branch_name
                patch.pr_url = result.pull_request_url
                patch.status = PatchStatus.DELIVERED.value
                await session.commit()
                delivered += 1
            except (UnsupportedRemediationError, UnicodeDecodeError, ValueError):
                logger.exception("Safe remediation rejected for finding %s", finding.id)
                failed += 1
            except Exception:
                logger.exception("GitHub remediation failed for finding %s", finding.id)
                failed += 1

    return RemediationSummary(delivered, skipped, failed)
