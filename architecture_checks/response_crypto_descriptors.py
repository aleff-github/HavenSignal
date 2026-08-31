"""Non-executing source policy for inert response crypto descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


RESPONSE_CRYPTO_DESCRIPTOR_PATH = (
    "security_interfaces/response_crypto_descriptors.py"
)
EXPECTED_RESPONSE_CRYPTO_DESCRIPTOR_AST_DIGEST = (
    "b602577184e9cbbfd6582b1e4b12c8a7b1471999f155f1676ca319f5971c73d3"
)


class ResponseCryptoDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class ResponseCryptoDescriptorSourceViolation:
    code: ResponseCryptoDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: ResponseCryptoDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> ResponseCryptoDescriptorSourceViolation:
    return ResponseCryptoDescriptorSourceViolation(
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


def analyze_response_crypto_descriptor_source(
    *,
    source: str,
    relative_path: str = RESPONSE_CRYPTO_DESCRIPTOR_PATH,
) -> tuple[ResponseCryptoDescriptorSourceViolation, ...]:
    """Compare the response crypto descriptor with its reviewed AST."""

    if relative_path != RESPONSE_CRYPTO_DESCRIPTOR_PATH:
        return (
            _violation(
                ResponseCryptoDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "RESPONSE_CRYPTO_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                ResponseCryptoDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_RESPONSE_CRYPTO_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                ResponseCryptoDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_RESPONSE_CRYPTO_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_response_crypto_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[ResponseCryptoDescriptorSourceViolation, ...]:
    """Read the reviewed response crypto descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                ResponseCryptoDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_response_crypto_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_response_crypto_descriptor(
    root: Path,
) -> tuple[ResponseCryptoDescriptorSourceViolation, ...]:
    """Run the non-executing response crypto descriptor source policy."""

    return scan_response_crypto_descriptor_source(
        path=root / RESPONSE_CRYPTO_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert response crypto descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_response_crypto_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
