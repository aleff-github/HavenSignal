"""Non-executing source policy for inert recovery verifier record descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


RECOVERY_VERIFIER_RECORD_DESCRIPTOR_PATH = (
    "security_interfaces/recovery_verifier_record_descriptors.py"
)
EXPECTED_RECOVERY_VERIFIER_RECORD_DESCRIPTOR_AST_DIGEST = (
    "fc376fd87388a031b38785f775794c8d6268b952c5febd80b0d2ce3fdde985c6"
)


class RecoveryVerifierRecordDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class RecoveryVerifierRecordDescriptorSourceViolation:
    code: RecoveryVerifierRecordDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: RecoveryVerifierRecordDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> RecoveryVerifierRecordDescriptorSourceViolation:
    return RecoveryVerifierRecordDescriptorSourceViolation(
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


def analyze_recovery_verifier_record_descriptor_source(
    *,
    source: str,
    relative_path: str = RECOVERY_VERIFIER_RECORD_DESCRIPTOR_PATH,
) -> tuple[RecoveryVerifierRecordDescriptorSourceViolation, ...]:
    """Compare the recovery verifier record descriptor with its reviewed AST."""

    if relative_path != RECOVERY_VERIFIER_RECORD_DESCRIPTOR_PATH:
        return (
            _violation(
                RecoveryVerifierRecordDescriptorSourceViolationCode.
                TARGET_SET_MISMATCH,
                relative_path,
                "RECOVERY_VERIFIER_RECORD_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                RecoveryVerifierRecordDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_RECOVERY_VERIFIER_RECORD_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                RecoveryVerifierRecordDescriptorSourceViolationCode.
                SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_RECOVERY_VERIFIER_RECORD_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_recovery_verifier_record_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[RecoveryVerifierRecordDescriptorSourceViolation, ...]:
    """Read the reviewed recovery verifier record descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                RecoveryVerifierRecordDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_recovery_verifier_record_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_recovery_verifier_record_descriptor(
    root: Path,
) -> tuple[RecoveryVerifierRecordDescriptorSourceViolation, ...]:
    """Run the non-executing recovery verifier record source policy."""

    return scan_recovery_verifier_record_descriptor_source(
        path=root / RECOVERY_VERIFIER_RECORD_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert recovery verifier record descriptor source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_recovery_verifier_record_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
