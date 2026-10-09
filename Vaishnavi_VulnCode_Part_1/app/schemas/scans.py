from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    cwe: str | None
    severity: str
    confidence: float
    path: str
    start_line: int
    end_line: int
    message: str


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_full_name: str
    commit_sha: str
    ref: str | None
    installation_id: int | None
    trigger: str
    status: str
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    findings: list[FindingResponse] = Field(default_factory=list)


class SemgrepIngestRequest(BaseModel):
    repository_full_name: str = Field(pattern=r"^[^/\s]+/[^/\s]+$")
    commit_sha: str = Field(min_length=7, max_length=64)
    ref: str | None = None
    installation_id: int | None = None
    semgrep: dict[str, Any]


class SemgrepIngestResponse(BaseModel):
    scan: ScanResponse
    normalized_findings: int
    github_check: str
