"""Non-executing exact-source policy for the inert Django bootstrap."""

import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class BootstrapSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class BootstrapSourceViolation:
    code: BootstrapSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS = MappingProxyType(
    {
        "anonymous_reporting/asgi.py": (
            "f42959c4ddd0ec9f30e61d6c0c6602b790259d7e14485592ba677beae50b8a89"
        ),
        "anonymous_reporting/wsgi.py": (
            "5a400046a9e968f3c6d86a4e5764f78a58c72f6e84e2ed091e094c761a0ef3cc"
        ),
        "manage.py": (
            "70e0c8d95ab2bd0d38761902d4848d0462f623f0e308de69bef397c0b6909774"
        ),
        "operator_console/apps.py": (
            "844fa7f1ddf8a9dc702582560244d32587dc93d658b28d863ac1fa665e658aeb"
        ),
        "recovery_gateway/apps.py": (
            "f6be3942860a22dd6362293c4e8a7a77fb287d6ed6bfb172383a542abe163cfe"
        ),
        "report_lifecycle/apps.py": (
            "1e9d5f00b03746b95a215354f41d75993498aa51801c82b4e0e397205b3026a1"
        ),
        "submission_workflow/apps.py": (
            "13c42451c5f8d75377459e3f7d3879eb63887f2fc832a2c86bd934a5f89934c4"
        ),
    }
)


def _violation(
    *,
    code: BootstrapSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> BootstrapSourceViolation:
    return BootstrapSourceViolation(
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


def analyze_bootstrap_source(
    *, source: str, relative_path: str
) -> tuple[BootstrapSourceViolation, ...]:
    """Compare one bootstrap target with its reviewed executable AST."""

    expected_digest = EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS.get(relative_path)
    if expected_digest is None:
        return (
            _violation(
                code=BootstrapSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path=relative_path,
                detail_code="UNKNOWN_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=BootstrapSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != expected_digest:
        return (
            _violation(
                code=BootstrapSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path=relative_path,
                detail_code="EXECUTABLE_AST",
            ),
        )
    return ()


def scan_bootstrap_sources(
    *, repository_root: Path
) -> tuple[BootstrapSourceViolation, ...]:
    """Read only the exact bootstrap targets beneath the repository root."""

    try:
        resolved_root = repository_root.resolve(strict=True)
    except OSError:
        return (
            _violation(
                code=BootstrapSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-scan-path>",
                detail_code="ROOT_INVALID",
            ),
        )
    violations: list[BootstrapSourceViolation] = []
    for relative_path in EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS:
        path = resolved_root / relative_path
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
            source = resolved_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            violations.append(
                _violation(
                    code=BootstrapSourceViolationCode.SOURCE_PARSE_ERROR,
                    relative_path="<invalid-scan-path>",
                    detail_code="TARGET_INVALID",
                )
            )
            continue
        violations.extend(
            analyze_bootstrap_source(
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
