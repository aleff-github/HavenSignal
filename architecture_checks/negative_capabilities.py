"""Non-executing source policy for mandatory unavailable security controls."""

import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class NegativeCapabilityViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class NegativeCapabilitySourceViolation:
    code: NegativeCapabilityViolationCode
    relative_path: str
    line: int
    detail_code: str


NEGATIVE_CAPABILITY_SOURCE_DIGESTS = MappingProxyType(
    {
        "security_interfaces/errors.py": (
            "fcb7a293047e84f29ee96815901360d4612dc2fb10c8c4cfdf47d2897aa3df8c"
        ),
        "security_interfaces/unavailable.py": (
            "bea992f14b9caf17465914314d75f5a298bb0bd8ccf80af595e4d27c4e329aea"
        ),
    }
)


def _violation(
    code: NegativeCapabilityViolationCode,
    relative_path: str,
    detail_code: str,
) -> NegativeCapabilitySourceViolation:
    return NegativeCapabilitySourceViolation(
        code=code,
        relative_path=relative_path,
        line=0,
        detail_code=detail_code,
    )


def analyze_negative_capability_source(
    *, source: str, relative_path: str
) -> tuple[NegativeCapabilitySourceViolation, ...]:
    """Lock one exact executable AST without importing or executing it."""

    expected_digest = NEGATIVE_CAPABILITY_SOURCE_DIGESTS.get(relative_path)
    if expected_digest is None:
        return (
            _violation(
                NegativeCapabilityViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                "EXACT_NEGATIVE_CAPABILITY_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                NegativeCapabilityViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    payload = ast.dump(
        tree,
        annotate_fields=True,
        include_attributes=False,
    ).encode("utf-8")
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        return (
            _violation(
                NegativeCapabilityViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path,
                "EXACT_FAIL_CLOSED_EXECUTABLE_AST",
            ),
        )
    return ()


def scan_negative_capability_sources(
    *, root: Path
) -> tuple[NegativeCapabilitySourceViolation, ...]:
    """Scan only the two fixed targets and fail closed on path/read errors."""

    violations: list[NegativeCapabilitySourceViolation] = []
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        return (
            _violation(
                NegativeCapabilityViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-root>",
                "TARGET_UNAVAILABLE",
            ),
        )
    for relative_path in NEGATIVE_CAPABILITY_SOURCE_DIGESTS:
        try:
            target = (resolved_root / relative_path).resolve(strict=True)
            target.relative_to(resolved_root)
            source = target.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            violations.append(
                _violation(
                    NegativeCapabilityViolationCode.SOURCE_PARSE_ERROR,
                    relative_path,
                    "TARGET_UNAVAILABLE",
                )
            )
            continue
        violations.extend(
            analyze_negative_capability_source(
                source=source,
                relative_path=relative_path,
            )
        )
    return tuple(violations)
