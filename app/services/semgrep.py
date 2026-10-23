from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    fingerprint: str
    rule_id: str
    cwe: str | None
    severity: str
    confidence: float
    path: str
    start_line: int
    end_line: int
    message: str
    evidence_json: str


_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "low",
    "EXPERIMENT": "low",
}

_CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}


def _first_cwe(metadata: dict[str, Any]) -> str | None:
    raw = metadata.get("cwe")
    values = raw if isinstance(raw, list) else [raw] if raw else []
    for value in values:
        match = re.search(r"CWE-\d+", str(value), flags=re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return None


def normalize_semgrep(payload: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in payload.get("results", []):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = str(result.get("check_id") or "unknown-rule")
        path = str(result.get("path") or "unknown")
        start_line = int((result.get("start") or {}).get("line") or 1)
        end_line = int((result.get("end") or {}).get("line") or start_line)
        severity = _SEVERITY_MAP.get(str(extra.get("severity") or "WARNING").upper(), "medium")
        confidence_name = str(metadata.get("confidence") or "MEDIUM").upper()
        confidence = _CONFIDENCE_MAP.get(confidence_name, 0.7)
        message = str(extra.get("message") or rule_id)
        raw_fingerprint = result.get("extra", {}).get("fingerprint")
        if not raw_fingerprint:
            raw_fingerprint = f"{rule_id}:{path}:{start_line}:{message}"
        fingerprint = hashlib.sha256(str(raw_fingerprint).encode("utf-8")).hexdigest()
        evidence = {
            "lines": extra.get("lines"),
            "metadata": metadata,
            "engine_kind": extra.get("engine_kind"),
        }
        findings.append(
            NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=rule_id,
                cwe=_first_cwe(metadata),
                severity=severity,
                confidence=confidence,
                path=path,
                start_line=start_line,
                end_line=end_line,
                message=message,
                evidence_json=json.dumps(evidence, separators=(",", ":"), default=str),
            )
        )
    return findings

