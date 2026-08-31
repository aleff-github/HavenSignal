"""Non-executing exact-source policy for the inert lifecycle core."""

import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class LifecycleSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class LifecycleSourceViolation:
    code: LifecycleSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS = MappingProxyType(
    {
        "report_lifecycle/bindings.py": (
            "a903b5c29a8fd25a7304a3f1d78f787a4ca9eabd29e359463658a08cd98eb59f"
        ),
        "report_lifecycle/errors.py": (
            "ff91d9736110052a1d64c1619427ffc63bd2c14a2067337b0a9417dfde47957f"
        ),
        "report_lifecycle/models.py": (
            "c5309a0d03d2d83442aa292d7603671ba411d6d35964bea274c6689983729cb4"
        ),
        "report_lifecycle/persistence.py": (
            "a717ea1bc61838c494e44135c7167047cce7890276a64bea1cd827ff694faeed"
        ),
        "report_lifecycle/states.py": (
            "42a04225df50b26c29e0eeb4bb52b823d9d731c0f4bf89606b16b34153490464"
        ),
        "report_lifecycle/transitions.py": (
            "e0083e4424199b6240ab7b7a799ffaf25c4ea2b8d326b6cdb8b8fe836ff9a030"
        ),
    }
)


def _violation(
    *,
    code: LifecycleSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> LifecycleSourceViolation:
    return LifecycleSourceViolation(
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


def analyze_lifecycle_source(
    *, source: str, relative_path: str
) -> tuple[LifecycleSourceViolation, ...]:
    """Compare one lifecycle target with its reviewed executable AST."""

    expected_digest = EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS.get(relative_path)
    if expected_digest is None:
        return (
            _violation(
                code=LifecycleSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path=relative_path,
                detail_code="UNKNOWN_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=LifecycleSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != expected_digest:
        return (
            _violation(
                code=LifecycleSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path=relative_path,
                detail_code="EXECUTABLE_AST",
            ),
        )
    return ()


def scan_lifecycle_sources(
    *, repository_root: Path
) -> tuple[LifecycleSourceViolation, ...]:
    """Read only the exact lifecycle targets beneath the repository root."""

    try:
        resolved_root = repository_root.resolve(strict=True)
    except OSError:
        return (
            _violation(
                code=LifecycleSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-scan-path>",
                detail_code="ROOT_INVALID",
            ),
        )
    violations: list[LifecycleSourceViolation] = []
    for relative_path in EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS:
        path = resolved_root / relative_path
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
            source = resolved_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            violations.append(
                _violation(
                    code=LifecycleSourceViolationCode.SOURCE_PARSE_ERROR,
                    relative_path="<invalid-scan-path>",
                    detail_code="TARGET_INVALID",
                )
            )
            continue
        violations.extend(
            analyze_lifecycle_source(
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
