"""Non-executing source policy for inert original-report crypto descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


REPORT_CRYPTO_DESCRIPTOR_PATH = "security_interfaces/report_crypto_descriptors.py"
EXPECTED_REPORT_CRYPTO_DESCRIPTOR_AST_DIGEST = (
    "a76100d89d6034ae6bbf854bf5208bc053e9d231281123c3a49d14c0c1f01492"
)


class ReportCryptoDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class ReportCryptoDescriptorSourceViolation:
    code: ReportCryptoDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: ReportCryptoDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> ReportCryptoDescriptorSourceViolation:
    return ReportCryptoDescriptorSourceViolation(
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


def analyze_report_crypto_descriptor_source(
    *,
    source: str,
    relative_path: str = REPORT_CRYPTO_DESCRIPTOR_PATH,
) -> tuple[ReportCryptoDescriptorSourceViolation, ...]:
    """Compare the report crypto descriptor with its reviewed AST."""

    if relative_path != REPORT_CRYPTO_DESCRIPTOR_PATH:
        return (
            _violation(
                ReportCryptoDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "REPORT_CRYPTO_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                ReportCryptoDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_REPORT_CRYPTO_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                ReportCryptoDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_REPORT_CRYPTO_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_report_crypto_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[ReportCryptoDescriptorSourceViolation, ...]:
    """Read the reviewed report crypto descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                ReportCryptoDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_report_crypto_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_report_crypto_descriptor(
    root: Path,
) -> tuple[ReportCryptoDescriptorSourceViolation, ...]:
    """Run the non-executing report crypto descriptor source policy."""

    return scan_report_crypto_descriptor_source(
        path=root / REPORT_CRYPTO_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert report crypto descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_report_crypto_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
