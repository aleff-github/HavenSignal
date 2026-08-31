"""Non-executing source policy for inert response schema descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


RESPONSE_SCHEMA_DESCRIPTOR_PATH = (
    "security_interfaces/response_schema_descriptors.py"
)
EXPECTED_RESPONSE_SCHEMA_DESCRIPTOR_AST_DIGEST = (
    "f8ce357f35a5c2589c21272b96c77b4242d4725a119b52c600bcfdc4875f79cb"
)


class ResponseSchemaDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class ResponseSchemaDescriptorSourceViolation:
    code: ResponseSchemaDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: ResponseSchemaDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> ResponseSchemaDescriptorSourceViolation:
    return ResponseSchemaDescriptorSourceViolation(
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


def analyze_response_schema_descriptor_source(
    *,
    source: str,
    relative_path: str = RESPONSE_SCHEMA_DESCRIPTOR_PATH,
) -> tuple[ResponseSchemaDescriptorSourceViolation, ...]:
    """Compare the response schema descriptor with its reviewed AST."""

    if relative_path != RESPONSE_SCHEMA_DESCRIPTOR_PATH:
        return (
            _violation(
                ResponseSchemaDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "RESPONSE_SCHEMA_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                ResponseSchemaDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_RESPONSE_SCHEMA_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                ResponseSchemaDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_RESPONSE_SCHEMA_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_response_schema_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[ResponseSchemaDescriptorSourceViolation, ...]:
    """Read the reviewed response schema descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                ResponseSchemaDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_response_schema_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_response_schema_descriptor(
    root: Path,
) -> tuple[ResponseSchemaDescriptorSourceViolation, ...]:
    """Run the non-executing response schema descriptor source policy."""

    return scan_response_schema_descriptor_source(
        path=root / RESPONSE_SCHEMA_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert response schema descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_response_schema_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
