from app.db.models import Finding, Scan
from app.integrations.github import build_scan_check_payload


def make_finding(*, cwe: str, path: str, rule_id: str) -> Finding:
    return Finding(
        id=f"finding-{cwe}",
        scan_id="scan-1",
        fingerprint=f"fingerprint-{cwe}",
        rule_id=rule_id,
        cwe=cwe,
        severity="high",
        confidence=0.9,
        path=path,
        start_line=4,
        end_line=4,
        message="test finding",
    )


def make_scan(finding: Finding) -> Scan:
    scan = Scan(
        id="scan-1",
        repository_full_name="vulncode/demo",
        commit_sha="a" * 40,
        ref="refs/heads/main",
        installation_id=123,
    )
    scan.findings = [finding]
    return scan


def test_check_run_exposes_native_fix_action_for_supported_findings() -> None:
    scan = make_scan(
        make_finding(cwe="CWE-89", path="users.py", rule_id="python.sql-injection")
    )
    payload = build_scan_check_payload(scan)

    assert payload["external_id"] == "scan-1"
    assert payload["actions"] == [
        {
            "label": "Create safe fixes",
            "description": "Generate validated fixes as draft pull requests",
            "identifier": "create_safe_fixes",
        }
    ]


def test_check_run_omits_fix_action_for_unsupported_findings() -> None:
    scan = make_scan(
        make_finding(cwe="CWE-78", path="commands.py", rule_id="python.command-injection")
    )
    assert "actions" not in build_scan_check_payload(scan)
