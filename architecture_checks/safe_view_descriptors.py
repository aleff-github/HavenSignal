"""Non-executing source policy for inert safe-view descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


SAFE_VIEW_DESCRIPTOR_PATH = "security_interfaces/safe_view_descriptors.py"
EXPECTED_SAFE_VIEW_DESCRIPTOR_AST_DIGEST = (
    "4ea356402c9db65f9dfa315d970d76037a0276d8c5e37e6bbc5beef7ebaa1a14"
)


class SafeViewDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class SafeViewDescriptorSourceViolation:
    code: SafeViewDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: SafeViewDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> SafeViewDescriptorSourceViolation:
    return SafeViewDescriptorSourceViolation(
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


def analyze_safe_view_descriptor_source(
    *,
    source: str,
    relative_path: str = SAFE_VIEW_DESCRIPTOR_PATH,
) -> tuple[SafeViewDescriptorSourceViolation, ...]:
    """Compare the safe-view descriptor with its reviewed AST."""

    if relative_path != SAFE_VIEW_DESCRIPTOR_PATH:
        return (
            _violation(
                SafeViewDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "SAFE_VIEW_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                SafeViewDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_SAFE_VIEW_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                SafeViewDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_SAFE_VIEW_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_safe_view_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[SafeViewDescriptorSourceViolation, ...]:
    """Read the reviewed safe-view descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                SafeViewDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_safe_view_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_safe_view_descriptor(
    root: Path,
) -> tuple[SafeViewDescriptorSourceViolation, ...]:
    """Run the non-executing safe-view descriptor source policy."""

    return scan_safe_view_descriptor_source(
        path=root / SAFE_VIEW_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert safe-view descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_safe_view_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
