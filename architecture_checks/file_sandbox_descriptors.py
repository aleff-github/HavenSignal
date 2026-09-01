"""Non-executing source policy for inert file-sandbox descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


FILE_SANDBOX_DESCRIPTOR_PATH = (
    "security_interfaces/file_sandbox_descriptors.py"
)
EXPECTED_FILE_SANDBOX_DESCRIPTOR_AST_DIGEST = (
    "5dcb13abef9389eca6b7aeab4e386a7e57f12bb65e10b35db1f27d27513736c7"
)


class FileSandboxDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class FileSandboxDescriptorSourceViolation:
    code: FileSandboxDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: FileSandboxDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> FileSandboxDescriptorSourceViolation:
    return FileSandboxDescriptorSourceViolation(
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


def analyze_file_sandbox_descriptor_source(
    *,
    source: str,
    relative_path: str = FILE_SANDBOX_DESCRIPTOR_PATH,
) -> tuple[FileSandboxDescriptorSourceViolation, ...]:
    """Compare the file-sandbox descriptor with its reviewed AST."""

    if relative_path != FILE_SANDBOX_DESCRIPTOR_PATH:
        return (
            _violation(
                FileSandboxDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "FILE_SANDBOX_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                FileSandboxDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_FILE_SANDBOX_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                FileSandboxDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_FILE_SANDBOX_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_file_sandbox_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[FileSandboxDescriptorSourceViolation, ...]:
    """Read the reviewed file-sandbox descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                FileSandboxDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_file_sandbox_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_file_sandbox_descriptor(
    root: Path,
) -> tuple[FileSandboxDescriptorSourceViolation, ...]:
    """Run the non-executing file-sandbox descriptor source policy."""

    return scan_file_sandbox_descriptor_source(
        path=root / FILE_SANDBOX_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert file-sandbox descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_file_sandbox_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
