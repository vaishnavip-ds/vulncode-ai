from __future__ import annotations

import json

import pytest

from app.db.models import Finding, PatchStatus
from app.services.patches import (
    UnsupportedRemediationError,
    build_patch,
    validate_patch,
)


def finding(*, cwe: str, path: str, rule_id: str) -> Finding:
    return Finding(
        id="finding-1",
        scan_id="scan-1",
        fingerprint="fingerprint",
        rule_id=rule_id,
        cwe=cwe,
        severity="high",
        confidence=0.9,
        path=path,
        start_line=1,
        end_line=1,
        message="test finding",
    )


def test_generates_and_validates_parameterized_sql_patch() -> None:
    item = finding(cwe="CWE-89", path="users.py", rule_id="python.sql-injection")
    source = (
        "def lookup(cursor, username):\n"
        '    cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\'")\n'
        "    return cursor.fetchone()\n"
    )
    patch = build_patch(item, source)
    patch.finding = item

    assert 'cursor.execute("SELECT * FROM users WHERE username = %s", (username,))' in (
        patch.patched_content
    )
    assert "@@" in patch.unified_diff
    report = validate_patch(patch)
    assert report.passed
    assert patch.status == PatchStatus.VALIDATED.value
    assert json.loads(patch.validation_json or "{}")["passed"] is True


def test_generates_text_content_patch_for_direct_dom_xss() -> None:
    item = finding(cwe="CWE-79", path="profile.js", rule_id="javascript.xss")
    patch = build_patch(item, "output.innerHTML = userInput;\n")
    patch.finding = item
    assert patch.patched_content == "output.textContent = userInput;\n"
    assert validate_patch(patch).passed


def test_rejects_unsupported_automatic_remediation() -> None:
    item = finding(cwe="CWE-78", path="commands.py", rule_id="python.command-injection")
    with pytest.raises(UnsupportedRemediationError):
        build_patch(item, "os.system(user_input)\n")

