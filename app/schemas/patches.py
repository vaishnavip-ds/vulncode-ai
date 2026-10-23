from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PatchGenerateRequest(BaseModel):
    finding_id: str
    source_content: str = Field(min_length=1, max_length=500_000)
    placeholder_style: str = Field(default="%s", pattern=r"^(%s|\?)$")


class ValidationCheckResponse(BaseModel):
    name: str
    passed: bool
    detail: str


class ValidationReportResponse(BaseModel):
    passed: bool
    checks: list[ValidationCheckResponse]


class PatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    patched_content: str
    unified_diff: str
    rationale: str
    generator: str
    status: str
    validation_json: str | None
    branch_name: str | None
    pr_url: str | None
    created_at: datetime
    updated_at: datetime


class PatchValidationResponse(BaseModel):
    patch: PatchResponse
    validation: ValidationReportResponse


class PatchDeliveryResponse(BaseModel):
    patch: PatchResponse
    pull_request_url: str


class PatchRejectRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)
