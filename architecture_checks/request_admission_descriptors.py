"""Non-executing source policy for inert request-admission descriptors."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


REQUEST_ADMISSION_DESCRIPTOR_PATH = (
    "security_interfaces/request_admission_descriptors.py"
)
EXPECTED_REQUEST_ADMISSION_DESCRIPTOR_AST_DIGEST = (
    "d3579c429b36ac9b9c47927dc25f1540463754589bbcf1b6c317b3ed42e385ec"
)


class RequestAdmissionDescriptorSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class RequestAdmissionDescriptorSourceViolation:
    code: RequestAdmissionDescriptorSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


def _violation(
    code: RequestAdmissionDescriptorSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> RequestAdmissionDescriptorSourceViolation:
    return RequestAdmissionDescriptorSourceViolation(
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


def analyze_request_admission_descriptor_source(
    *,
    source: str,
    relative_path: str = REQUEST_ADMISSION_DESCRIPTOR_PATH,
) -> tuple[RequestAdmissionDescriptorSourceViolation, ...]:
    """Compare the request-admission descriptor with its reviewed AST."""

    if relative_path != REQUEST_ADMISSION_DESCRIPTOR_PATH:
        return (
            _violation(
                RequestAdmissionDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "REQUEST_ADMISSION_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                RequestAdmissionDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != EXPECTED_REQUEST_ADMISSION_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                RequestAdmissionDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_INERT_REQUEST_ADMISSION_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_request_admission_descriptor_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[RequestAdmissionDescriptorSourceViolation, ...]:
    """Read the reviewed request-admission descriptor or fail closed."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                RequestAdmissionDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_request_admission_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def scan_repository_request_admission_descriptor(
    root: Path,
) -> tuple[RequestAdmissionDescriptorSourceViolation, ...]:
    """Run the non-executing request-admission descriptor source policy."""

    return scan_request_admission_descriptor_source(
        path=root / REQUEST_ADMISSION_DESCRIPTOR_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert request-admission descriptor source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_request_admission_descriptor(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
