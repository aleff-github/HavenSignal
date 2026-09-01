"""Non-executing source policy for inert submission-reconciliation descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


SUBMISSION_RECONCILIATION_DESCRIPTOR_PATH = (
    "security_interfaces/submission_reconciliation_descriptors.py"
)
EXPECTED_SUBMISSION_RECONCILIATION_DESCRIPTOR_AST_DIGEST = (
    "ff1ee821789ea709454deb2d5ee55a4655a01420e729cf9823d7010791c26e1a"
)


class SubmissionReconciliationDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class SubmissionReconciliationDescriptorSourceViolation:
    code: SubmissionReconciliationDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: SubmissionReconciliationDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> SubmissionReconciliationDescriptorSourceViolation:
    return SubmissionReconciliationDescriptorSourceViolation(
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


def analyze_submission_reconciliation_descriptor_source(
    *,
    source: str,
    relative_path: str = SUBMISSION_RECONCILIATION_DESCRIPTOR_PATH,
) -> tuple[SubmissionReconciliationDescriptorSourceViolation, ...]:
    """Compare the submission-reconciliation descriptor with its reviewed AST."""

    if relative_path != SUBMISSION_RECONCILIATION_DESCRIPTOR_PATH:
        return (
            _violation(
                (
                    SubmissionReconciliationDescriptorSourceViolationCode.
                    TARGET_SET_MISMATCH
                ),
                relative_path,
                "SUBMISSION_RECONCILIATION_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                (
                    SubmissionReconciliationDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != (
        EXPECTED_SUBMISSION_RECONCILIATION_DESCRIPTOR_AST_DIGEST
    ):
        return (
            _violation(
                (
                    SubmissionReconciliationDescriptorSourceViolationCode.
                    SOURCE_PROFILE_MISMATCH
                ),
                relative_path,
                "EXACT_INERT_SUBMISSION_RECONCILIATION_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_submission_reconciliation_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[SubmissionReconciliationDescriptorSourceViolation, ...]:
    """Read the reviewed submission-reconciliation descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                (
                    SubmissionReconciliationDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_submission_reconciliation_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_submission_reconciliation_descriptor(
    root: Path,
) -> tuple[SubmissionReconciliationDescriptorSourceViolation, ...]:
    """Run the non-executing reconciliation descriptor source policy."""

    return scan_submission_reconciliation_descriptor_source(
        path=root / SUBMISSION_RECONCILIATION_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert submission-reconciliation descriptor source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_submission_reconciliation_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
