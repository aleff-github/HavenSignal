"""Non-executing exact-source policy for the inert submission workflow."""

import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class SubmissionSourceViolationCode(StrEnum):
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    SOURCE_PROFILE_MISMATCH = "SOURCE_PROFILE_MISMATCH"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class SubmissionSourceViolation:
    code: SubmissionSourceViolationCode
    relative_path: str
    line: int
    detail_code: str


EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS = MappingProxyType(
    {
        "submission_workflow/errors.py": (
            "f6b7b9e34d4082665b8020e573996431574a5ea79b2f3fa8e3249912f2417cd9"
        ),
        "submission_workflow/models.py": (
            "208b85d9f1aee900e75028c8f0de023d636934650001239bd4aab36dcc05635b"
        ),
        "submission_workflow/states.py": (
            "c35749d457e6cfb63b5fa2610bad222d7b1157671fd64615c83330205e9ffa0c"
        ),
        "submission_workflow/transitions.py": (
            "90dd407b2c7f2157988599c5f614f3927c68654efe5c4103743ae283c97e92f5"
        ),
    }
)


def _violation(
    *,
    code: SubmissionSourceViolationCode,
    relative_path: str,
    detail_code: str,
) -> SubmissionSourceViolation:
    return SubmissionSourceViolation(
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


def analyze_submission_source(
    *, source: str, relative_path: str
) -> tuple[SubmissionSourceViolation, ...]:
    """Compare one target AST with its reviewed inert profile."""

    expected_digest = EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS.get(relative_path)
    if expected_digest is None:
        return (
            _violation(
                code=SubmissionSourceViolationCode.TARGET_SET_MISMATCH,
                relative_path=relative_path,
                detail_code="UNKNOWN_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=SubmissionSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )
    if _ast_digest(tree) != expected_digest:
        return (
            _violation(
                code=SubmissionSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                relative_path=relative_path,
                detail_code="EXECUTABLE_AST",
            ),
        )
    return ()


def scan_submission_sources(
    *, repository_root: Path
) -> tuple[SubmissionSourceViolation, ...]:
    """Read only the exact submission targets beneath the repository root."""

    try:
        resolved_root = repository_root.resolve(strict=True)
    except OSError:
        return (
            _violation(
                code=SubmissionSourceViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-scan-path>",
                detail_code="ROOT_INVALID",
            ),
        )
    violations: list[SubmissionSourceViolation] = []
    for relative_path in EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS:
        path = resolved_root / relative_path
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
            source = resolved_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            violations.append(
                _violation(
                    code=SubmissionSourceViolationCode.SOURCE_PARSE_ERROR,
                    relative_path="<invalid-scan-path>",
                    detail_code="TARGET_INVALID",
                )
            )
            continue
        violations.extend(
            analyze_submission_source(
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
