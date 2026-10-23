from app.services.semgrep import normalize_semgrep


def test_normalizes_semgrep_result() -> None:
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": "app/users.py",
                "start": {"line": 12},
                "end": {"line": 13},
                "extra": {
                    "message": "User input reaches a SQL query.",
                    "severity": "ERROR",
                    "fingerprint": "stable-fingerprint",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH"},
                },
            }
        ]
    }
    findings = normalize_semgrep(payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python.lang.security.audit.sqli"
    assert finding.cwe == "CWE-89"
    assert finding.severity == "high"
    assert finding.confidence == 0.9
    assert finding.path == "app/users.py"
    assert finding.start_line == 12


def test_empty_results_are_valid() -> None:
    assert normalize_semgrep({"results": []}) == []

