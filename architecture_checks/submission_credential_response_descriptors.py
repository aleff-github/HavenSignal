"""Non-executing source policy for inert credential-response descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_PATH = (
    "security_interfaces/submission_credential_response_descriptors.py"
)
EXPECTED_SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_AST_DIGEST = (
    "ee2b40789b34be6c9020552c1d2ed428fd5af5e52cb3cbbb11aadb496537893e"
)


class SubmissionCredentialResponseDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class SubmissionCredentialResponseDescriptorSourceViolation:
    code: SubmissionCredentialResponseDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: SubmissionCredentialResponseDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> SubmissionCredentialResponseDescriptorSourceViolation:
    return SubmissionCredentialResponseDescriptorSourceViolation(
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


def analyze_submission_credential_response_descriptor_source(
    *,
    source: str,
    relative_path: str = SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_PATH,
) -> tuple[SubmissionCredentialResponseDescriptorSourceViolation, ...]:
    """Compare the credential-response descriptor with its reviewed AST."""

    if relative_path != SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_PATH:
        return (
            _violation(
                (
                    SubmissionCredentialResponseDescriptorSourceViolationCode.
                    TARGET_SET_MISMATCH
                ),
                relative_path,
                "SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                (
                    SubmissionCredentialResponseDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != (
        EXPECTED_SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_AST_DIGEST
    ):
        return (
            _violation(
                (
                    SubmissionCredentialResponseDescriptorSourceViolationCode.
                    SOURCE_PROFILE_MISMATCH
                ),
                relative_path,
                "EXACT_INERT_SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_submission_credential_response_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[SubmissionCredentialResponseDescriptorSourceViolation, ...]:
    """Read the reviewed credential-response descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                (
                    SubmissionCredentialResponseDescriptorSourceViolationCode.
                    SOURCE_PARSE_ERROR
                ),
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_submission_credential_response_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_submission_credential_response_descriptor(
    root: Path,
) -> tuple[SubmissionCredentialResponseDescriptorSourceViolation, ...]:
    """Run the non-executing credential-response descriptor source policy."""

    return scan_submission_credential_response_descriptor_source(
        path=root / SUBMISSION_CREDENTIAL_RESPONSE_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert credential-response descriptor source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_submission_credential_response_descriptor(
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
