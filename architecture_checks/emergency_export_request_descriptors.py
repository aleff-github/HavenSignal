"""Non-executing source policy for inert Emergency Export request metadata."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_PATH = (
    "security_interfaces/emergency_export_request_descriptors.py"
)
EXPECTED_EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_AST_DIGEST = (
    "6fa2a184d7798408860604fa7b6f1bb1844ae33b6c9ac73308be9c3edb705e9a"
)


class EmergencyExportRequestDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class EmergencyExportRequestDescriptorSourceViolation:
    code: EmergencyExportRequestDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: EmergencyExportRequestDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> EmergencyExportRequestDescriptorSourceViolation:
    return EmergencyExportRequestDescriptorSourceViolation(
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


def analyze_emergency_export_request_descriptor_source(
    *,
    source: str,
    relative_path: str = EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_PATH,
) -> tuple[EmergencyExportRequestDescriptorSourceViolation, ...]:
    """Compare the export-request descriptor with its reviewed AST."""

    if relative_path != EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_PATH:
        return (
            _violation(
                EmergencyExportRequestDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                EmergencyExportRequestDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                EmergencyExportRequestDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_emergency_export_request_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[EmergencyExportRequestDescriptorSourceViolation, ...]:
    """Read the reviewed export-request descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                EmergencyExportRequestDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_emergency_export_request_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_emergency_export_request_descriptor(
    root: Path,
) -> tuple[EmergencyExportRequestDescriptorSourceViolation, ...]:
    """Run the non-executing export-request descriptor source policy."""

    return scan_emergency_export_request_descriptor_source(
        path=root / EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the inert Emergency Export request descriptor source profile."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_emergency_export_request_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
