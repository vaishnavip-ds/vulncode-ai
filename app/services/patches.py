from __future__ import annotations

import ast
import difflib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Protocol

from app.db.models import Finding, Patch, PatchStatus


class UnsupportedRemediationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PatchProposal:
    patched_content: str
    unified_diff: str
    rationale: str
    generator: str


@dataclass(frozen=True, slots=True)
class ValidationCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ValidationReport:
    passed: bool
    checks: list[ValidationCheck]

    def to_json(self) -> str:
        return json.dumps(
            {"passed": self.passed, "checks": [asdict(check) for check in self.checks]},
            separators=(",", ":"),
        )


class PatchGenerator(Protocol):
    def generate(
        self, finding: Finding, source_content: str, *, placeholder_style: str = "%s"
    ) -> PatchProposal: ...


class RuleBasedPatchGenerator:
    """Conservative fixes for two auditable prototype vulnerability patterns."""

    name = "rules-v1"
    _sql_execute = re.compile(
        r"(?P<receiver>\b[A-Za-z_]\w*)\.execute\(f(?P<quote>[\"'])"
        r"(?P<sql>[^\n]*?\{(?P<expression>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\}[^\n]*?)"
        r"(?P=quote)\)"
    )
    _inner_html = re.compile(
        r"(?P<receiver>\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.innerHTML\s*=\s*"
        r"(?P<expression>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;?"
    )

    def generate(
        self, finding: Finding, source_content: str, *, placeholder_style: str = "%s"
    ) -> PatchProposal:
        path = PurePosixPath(finding.path)
        cwe = (finding.cwe or "").upper()
        rule = finding.rule_id.lower()
        if path.suffix == ".py" and (cwe == "CWE-89" or "sql" in rule):
            return self._fix_python_sql(finding.path, source_content, placeholder_style)
        if path.suffix in {".js", ".jsx", ".ts", ".tsx"} and (
            cwe == "CWE-79" or "xss" in rule
        ):
            return self._fix_dom_xss(finding.path, source_content)
        raise UnsupportedRemediationError(
            f"No deterministic remediation is available for {finding.cwe or finding.rule_id} "
            f"in {path.suffix or 'this file type'}"
        )

    def _fix_python_sql(
        self, path: str, source: str, placeholder_style: str
    ) -> PatchProposal:
        if placeholder_style not in {"%s", "?"}:
            raise ValueError("placeholder_style must be '%s' or '?'")
        match = self._sql_execute.search(source)
        if not match:
            raise UnsupportedRemediationError(
                "The SQL finding does not match the supported single-expression f-string pattern"
            )
        sql = match.group("sql")
        expression = match.group("expression")
        quoted_expression = "'{" + expression + "}'"
        parameterized_sql = sql.replace(quoted_expression, placeholder_style)
        if parameterized_sql == sql:
            parameterized_sql = sql.replace("{" + expression + "}", placeholder_style)
        replacement = (
            f'{match.group("receiver")}.execute('
            f'"{parameterized_sql}", ({expression},))'
        )
        patched = source[: match.start()] + replacement + source[match.end() :]
        return self._proposal(
            path,
            source,
            patched,
            "Replaced SQL string interpolation with a bound query parameter.",
        )

    def _fix_dom_xss(self, path: str, source: str) -> PatchProposal:
        match = self._inner_html.search(source)
        if not match:
            raise UnsupportedRemediationError(
                "The XSS finding does not match the supported direct innerHTML assignment pattern"
            )
        replacement = f'{match.group("receiver")}.textContent = {match.group("expression")};'
        patched = source[: match.start()] + replacement + source[match.end() :]
        return self._proposal(
            path,
            source,
            patched,
            "Replaced HTML interpretation with text-only DOM assignment.",
        )

    def _proposal(self, path: str, source: str, patched: str, rationale: str) -> PatchProposal:
        if source == patched:
            raise UnsupportedRemediationError("The generator did not produce a code change")
        diff = "".join(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
            )
        )
        return PatchProposal(
            patched_content=patched,
            unified_diff=diff,
            rationale=rationale,
            generator=self.name,
        )


class DeterministicValidator:
    _dangerous_additions = (
        "eval(",
        "exec(",
        "shell=True",
        "verify=False",
        "pickle.loads(",
    )

    def validate(self, patch: Patch) -> ValidationReport:
        checks = [
            self._changed(patch),
            self._bounded_change(patch),
            self._no_new_dangerous_primitives(patch),
        ]
        suffix = PurePosixPath(patch.finding.path).suffix
        if suffix == ".py":
            checks.append(self._python_syntax(patch.patched_content))
        return ValidationReport(passed=all(check.passed for check in checks), checks=checks)

    def _changed(self, patch: Patch) -> ValidationCheck:
        passed = patch.original_content != patch.patched_content
        return ValidationCheck("content_changed", passed, "Patch changes source content.")

    def _bounded_change(self, patch: Patch) -> ValidationCheck:
        changed_lines = sum(
            1
            for line in patch.unified_diff.splitlines()
            if (line.startswith("+") or line.startswith("-"))
            and not line.startswith(("+++", "---"))
        )
        passed = 0 < changed_lines <= 40
        return ValidationCheck(
            "bounded_change",
            passed,
            f"Patch changes {changed_lines} line(s); the prototype limit is 40.",
        )

    def _no_new_dangerous_primitives(self, patch: Patch) -> ValidationCheck:
        added = [
            value
            for value in self._dangerous_additions
            if value in patch.patched_content and value not in patch.original_content
        ]
        return ValidationCheck(
            "no_new_dangerous_primitives",
            not added,
            "No new dangerous primitives were introduced."
            if not added
            else f"Introduced prohibited primitive(s): {', '.join(added)}",
        )

    def _python_syntax(self, source: str) -> ValidationCheck:
        try:
            ast.parse(source)
        except SyntaxError as error:
            return ValidationCheck(
                "python_ast",
                False,
                f"Python syntax failed at line {error.lineno}: {error.msg}",
            )
        return ValidationCheck("python_ast", True, "Python AST parsing passed.")


def supports_finding(finding: Finding) -> bool:
    path = PurePosixPath(finding.path)
    cwe = (finding.cwe or "").upper()
    rule = finding.rule_id.lower()
    return (
        path.suffix == ".py" and (cwe == "CWE-89" or "sql" in rule)
    ) or (
        path.suffix in {".js", ".jsx", ".ts", ".tsx"}
        and (cwe == "CWE-79" or "xss" in rule)
    )


def build_patch(finding: Finding, source_content: str, placeholder_style: str = "%s") -> Patch:
    proposal = RuleBasedPatchGenerator().generate(
        finding, source_content, placeholder_style=placeholder_style
    )
    return Patch(
        finding_id=finding.id,
        original_content=source_content,
        patched_content=proposal.patched_content,
        unified_diff=proposal.unified_diff,
        rationale=proposal.rationale,
        generator=proposal.generator,
        status=PatchStatus.GENERATED.value,
    )


def validate_patch(patch: Patch) -> ValidationReport:
    report = DeterministicValidator().validate(patch)
    patch.validation_json = report.to_json()
    patch.status = (
        PatchStatus.VALIDATED.value if report.passed else PatchStatus.REJECTED.value
    )
    return report
