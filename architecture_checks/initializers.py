"""Non-executing exact-source policy for application package initializers."""

import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class InitializerSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class InitializerSourceViolation:
    code: InitializerSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS = MappingProxyType(
    {
        "anonymous_reporting/__init__.py": (
            "505f9dc9d894f75c5a8033f373e0b88fa108306b3f01719600e4aa5cf5cf1691"
        ),
        "report_lifecycle/__init__.py": (
            "b9ba94e16ede68eab739a66e985a2808e95429186717eff3ffc208458d053888"
        ),
        "report_lifecycle/migrations/__init__.py": (
            "ad2e13b69c4fc1fda46413f740f426fc1793cfc6d6da8d226ba619f1aef48be7"
        ),
        "reporter_gateway/__init__.py": (
            "d3b736ebfc4ebdca6ece0d77a35315cf9fc5ccdcf4597bfa97367f4f689f8af3"
        ),
        "security_interfaces/__init__.py": (
            "ba022c800ef3460e96da233de95e19ca93b57454deeba5550eb122448be96439"
        ),
        "submission_workflow/__init__.py": (
            "8f01144fb792c83a2751099ae0c6c2ee2926c53a3bb9be71d43ec7a5c05ab6e2"
        ),
        "submission_workflow/migrations/__init__.py": (
            "ad2e13b69c4fc1fda46413f740f426fc1793cfc6d6da8d226ba619f1aef48be7"
        ),
    }
)


def _violation(
    *,
    code: InitializerSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> InitializerSourceViolation:
    return InitializerSourceViolation(
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


def analyze_initializer_source(
    *, source: str, relative_path: str
) -> tuple[InitializerSourceViolation, ...]:
    """Compare one initializer with its reviewed executable AST."""

    expected_digest = EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS.get(relative_path)
    if expected_digest is None:
        return (
            _violation(
                code=InitializerSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path=relative_path,
                detail_code="UNKNOWN_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=InitializerSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != expected_digest:
        return (
            _violation(
                code=InitializerSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path=relative_path,
                detail_code="EXECUTABLE_AST",
            ),
        )
    return ()


def scan_initializer_sources(
    *, repository_root: Path
) -> tuple[InitializerSourceViolation, ...]:
    """Read only the exact initializers beneath the repository root."""

    try:
        resolved_root = repository_root.resolve(strict=True)
    except OSError:
        return (
            _violation(
                code=InitializerSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-scan-path>",
                detail_code="ROOT_INVALID",
            ),
        )
    violations: list[InitializerSourceViolation] = []
    for relative_path in EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS:
        path = resolved_root / relative_path
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
            source = resolved_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            violations.append(
                _violation(
                    code=InitializerSourceViolationCode.SOURCE_PARSE_ERROR,
                    relative_path="<invalid-scan-path>",
                    detail_code="TARGET_INVALID",
                )
            )
            continue
        violations.extend(
            analyze_initializer_source(
                source=source,
                relative_path=relative_path,
            )
        )
    return tuple(
        sorted(
            violations,
            key=lambda item: (
                item.relative_path,
                item.code.value,
                item.detail_code,
            ),
        )
    )
