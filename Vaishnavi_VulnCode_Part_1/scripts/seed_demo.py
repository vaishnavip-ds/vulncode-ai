from __future__ import annotations

import asyncio
import hashlib

from sqlalchemy import select

from app.db.models import Finding, Patch, Scan, ScanStatus
from app.db.session import SessionFactory, create_schema
from app.services.patches import build_patch, validate_patch

SOURCE = '''def get_user_by_username(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
'''


async def seed() -> None:
    await create_schema()
    async with SessionFactory() as session:
        existing = await session.scalar(
            select(Scan).where(Scan.repository_full_name == "acme/payments-api")
        )
        if existing:
            print(f"Demo scan already exists: {existing.id}")
            return

        scan = Scan(
            repository_full_name="acme/payments-api",
            commit_sha="a3f9c2e1b47c0123456789abcdef0123456789ab",
            ref="refs/heads/main",
            trigger="demo_seed",
            status=ScanStatus.COMPLETED.value,
        )
        session.add(scan)
        await session.flush()

        findings = [
            Finding(
                scan_id=scan.id,
                fingerprint=hashlib.sha256(b"demo-sql").hexdigest(),
                rule_id="python.sql-injection",
                cwe="CWE-89",
                severity="critical",
                confidence=0.96,
                path="src/db/users.py",
                start_line=42,
                end_line=42,
                message="User input is interpolated directly into a SQL query.",
            ),
            Finding(
                scan_id=scan.id,
                fingerprint=hashlib.sha256(b"demo-xss").hexdigest(),
                rule_id="javascript.xss",
                cwe="CWE-79",
                severity="high",
                confidence=0.91,
                path="src/web/profile.ts",
                start_line=88,
                end_line=88,
                message="Untrusted content is assigned to innerHTML.",
            ),
            Finding(
                scan_id=scan.id,
                fingerprint=hashlib.sha256(b"demo-command").hexdigest(),
                rule_id="python.command-injection",
                cwe="CWE-78",
                severity="high",
                confidence=0.88,
                path="src/utils/exec.py",
                start_line=27,
                end_line=27,
                message="User-controlled data reaches a shell command.",
            ),
        ]
        session.add_all(findings)
        await session.flush()

        patch: Patch = build_patch(findings[0], SOURCE)
        patch.finding = findings[0]
        validate_patch(patch)
        session.add(patch)
        await session.commit()
        print(f"Created demo scan {scan.id} with {len(findings)} findings")


if __name__ == "__main__":
    asyncio.run(seed())
