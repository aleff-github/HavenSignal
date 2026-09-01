"""Non-executing source policy for inert attempt-credential descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_PATH = (
    "security_interfaces/submission_attempt_credential_descriptors.py"
)
EXPECTED_SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_AST_DIGEST = (
    "ad9510cb24126d7bb8b0fdee3f5148668b178bbbcb617cf916665a34c687b22a"
)


class SubmissionAttemptCredentialDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class SubmissionAttemptCredentialDescriptorSourceViolation:
    code: SubmissionAttemptCredentialDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: SubmissionAttemptCredentialDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> SubmissionAttemptCredentialDescriptorSourceViolation:
    return SubmissionAttemptCredentialDescriptorSourceViolation(
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


def analyze_submission_attempt_credential_descriptor_source(
    *,
    source: str,
    relative_path: str = SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_PATH,
) -> tuple[SubmissionAttemptCredentialDescriptorSourceViolation, ...]:
    """Compare the attempt-credential descriptor with its reviewed AST."""

    if relative_path != SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_PATH:
        return (
            _violation(
                (
                    SubmissionAttemptCredentialDescriptorSourceViolationCode.
                    TARGET_SET_MISMATCH
                ),
                relative_path,
                "SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                (
                    SubmissionAttemptCredentialDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != (
        EXPECTED_SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_AST_DIGEST
    ):
        return (
            _violation(
                (
                    SubmissionAttemptCredentialDescriptorSourceViolationCode.
                    SOURCE_PROFILE_MISMATCH
                ),
                relative_path,
                "EXACT_INERT_SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_submission_attempt_credential_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[SubmissionAttemptCredentialDescriptorSourceViolation, ...]:
    """Read the reviewed attempt-credential descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                (
                    SubmissionAttemptCredentialDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_submission_attempt_credential_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_submission_attempt_credential_descriptor(
    root: Path,
) -> tuple[SubmissionAttemptCredentialDescriptorSourceViolation, ...]:
    """Run the non-executing attempt-credential descriptor source policy."""

    return scan_submission_attempt_credential_descriptor_source(
        path=root / SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert attempt-credential descriptor source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_submission_attempt_credential_descriptor(
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
