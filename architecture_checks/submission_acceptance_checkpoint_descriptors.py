"""Non-executing source policy for inert submission-acceptance checkpoints."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_PATH = (
    "security_interfaces/submission_acceptance_checkpoint_descriptors.py"
)
EXPECTED_SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_AST_DIGEST = (
    "9fd5d825512e281fd58b702857764e8cb9c63093ec815e162955318962f2ca51"
)


class SubmissionAcceptanceCheckpointDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class SubmissionAcceptanceCheckpointDescriptorSourceViolation:
    code: SubmissionAcceptanceCheckpointDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: SubmissionAcceptanceCheckpointDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> SubmissionAcceptanceCheckpointDescriptorSourceViolation:
    return SubmissionAcceptanceCheckpointDescriptorSourceViolation(
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


def analyze_submission_acceptance_checkpoint_descriptor_source(
    *,
    source: str,
    relative_path: str = SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_PATH,
) -> tuple[SubmissionAcceptanceCheckpointDescriptorSourceViolation, ...]:
    """Compare the checkpoint descriptor with its reviewed AST."""

    if relative_path != SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_PATH:
        return (
            _violation(
                (
                    SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                    TARGET_SET_MISMATCH
                ),
                relative_path,
                "SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                (
                    SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if (
        _ast_digest(tree)
        != EXPECTED_SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_AST_DIGEST
    ):
        return (
            _violation(
                (
                    SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                    SOURCE_PROFILE_MISMATCH
                ),
                relative_path,
                "EXACT_INERT_SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_submission_acceptance_checkpoint_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[SubmissionAcceptanceCheckpointDescriptorSourceViolation, ...]:
    """Read the reviewed checkpoint descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                (
                    SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_submission_acceptance_checkpoint_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_submission_acceptance_checkpoint_descriptor(
    root: Path,
) -> tuple[SubmissionAcceptanceCheckpointDescriptorSourceViolation, ...]:
    """Run the non-executing checkpoint descriptor source policy."""

    return scan_submission_acceptance_checkpoint_descriptor_source(
        path=root / SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert submission-acceptance checkpoint descriptor "
            "source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_submission_acceptance_checkpoint_descriptor(
        args.root
    )
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
