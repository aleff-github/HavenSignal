"""Non-executing source policy for inert recovery verification descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


RECOVERY_VERIFICATION_DESCRIPTOR_PATH = (
    "security_interfaces/recovery_verification_descriptors.py"
)
EXPECTED_RECOVERY_VERIFICATION_DESCRIPTOR_AST_DIGEST = (
    "bb576eaac33ebf3f6ee634001fcafec8ccc1a97a9a6666a25b14133034238990"
)


class RecoveryVerificationDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class RecoveryVerificationDescriptorSourceViolation:
    code: RecoveryVerificationDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: RecoveryVerificationDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> RecoveryVerificationDescriptorSourceViolation:
    return RecoveryVerificationDescriptorSourceViolation(
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


def analyze_recovery_verification_descriptor_source(
    *,
    source: str,
    relative_path: str = RECOVERY_VERIFICATION_DESCRIPTOR_PATH,
) -> tuple[RecoveryVerificationDescriptorSourceViolation, ...]:
    """Compare the recovery verification descriptor with its reviewed AST."""

    if relative_path != RECOVERY_VERIFICATION_DESCRIPTOR_PATH:
        return (
            _violation(
                RecoveryVerificationDescriptorSourceViolationCode.
                TARGET_SET_MISMATCH,
                relative_path,
                "RECOVERY_VERIFICATION_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                RecoveryVerificationDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_RECOVERY_VERIFICATION_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                RecoveryVerificationDescriptorSourceViolationCode.
                SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_RECOVERY_VERIFICATION_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_recovery_verification_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[RecoveryVerificationDescriptorSourceViolation, ...]:
    """Read the reviewed recovery verification descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                RecoveryVerificationDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_recovery_verification_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_recovery_verification_descriptor(
    root: Path,
) -> tuple[RecoveryVerificationDescriptorSourceViolation, ...]:
    """Run the non-executing recovery verification descriptor source policy."""

    return scan_recovery_verification_descriptor_source(
        path=root / RECOVERY_VERIFICATION_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert recovery verification descriptor source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_recovery_verification_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
