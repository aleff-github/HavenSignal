"""Non-executing source policy for inert original-report text descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


REPORT_TEXT_DESCRIPTOR_PATH = "security_interfaces/report_text_descriptors.py"
EXPECTED_REPORT_TEXT_DESCRIPTOR_AST_DIGEST = (
    "f0a4a36415504eb37d9b016ffae23198df447e8bde855e2f06738802a207db63"
)


class ReportTextDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class ReportTextDescriptorSourceViolation:
    code: ReportTextDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: ReportTextDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> ReportTextDescriptorSourceViolation:
    return ReportTextDescriptorSourceViolation(
        code=code,
        relative_path=relative_path,
        line=0,
        detail_code=detail_code,
    )


def _ast_digest(tree: ast.AST) -> str:
    payload = ast.dump(
        tree,
        annotate_fields=True,
        include_attributes=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def analyze_report_text_descriptor_source(
    *,
    source: str,
    relative_path: str = REPORT_TEXT_DESCRIPTOR_PATH,
) -> tuple[ReportTextDescriptorSourceViolation, ...]:
    """Compare the report text descriptor with its reviewed AST."""

    if relative_path != REPORT_TEXT_DESCRIPTOR_PATH:
        return (
            _violation(
                ReportTextDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "REPORT_TEXT_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                ReportTextDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_REPORT_TEXT_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                ReportTextDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_REPORT_TEXT_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_report_text_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[ReportTextDescriptorSourceViolation, ...]:
    """Read the reviewed report text descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                ReportTextDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_report_text_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_report_text_descriptor(
    root: Path,
) -> tuple[ReportTextDescriptorSourceViolation, ...]:
    """Run the non-executing report text descriptor source policy."""

    return scan_report_text_descriptor_source(
        path=root / REPORT_TEXT_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert report text descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_report_text_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
