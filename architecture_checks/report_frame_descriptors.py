"""Non-executing source policy for inert original-report frame descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


REPORT_FRAME_DESCRIPTOR_PATH = "security_interfaces/report_frame_descriptors.py"
EXPECTED_REPORT_FRAME_DESCRIPTOR_AST_DIGEST = (
    "b56cfa7ac3943f8af645bf9b4d410a5ac2c9614c52424ea41257622d141a622d"
)


class ReportFrameDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class ReportFrameDescriptorSourceViolation:
    code: ReportFrameDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: ReportFrameDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> ReportFrameDescriptorSourceViolation:
    return ReportFrameDescriptorSourceViolation(
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


def analyze_report_frame_descriptor_source(
    *,
    source: str,
    relative_path: str = REPORT_FRAME_DESCRIPTOR_PATH,
) -> tuple[ReportFrameDescriptorSourceViolation, ...]:
    """Compare the report frame descriptor with its reviewed AST."""

    if relative_path != REPORT_FRAME_DESCRIPTOR_PATH:
        return (
            _violation(
                ReportFrameDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "REPORT_FRAME_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                ReportFrameDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_REPORT_FRAME_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                ReportFrameDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_REPORT_FRAME_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_report_frame_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[ReportFrameDescriptorSourceViolation, ...]:
    """Read the reviewed report frame descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                ReportFrameDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_report_frame_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_report_frame_descriptor(
    root: Path,
) -> tuple[ReportFrameDescriptorSourceViolation, ...]:
    """Run the non-executing report frame descriptor source policy."""

    return scan_report_frame_descriptor_source(
        path=root / REPORT_FRAME_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert report frame descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_report_frame_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
