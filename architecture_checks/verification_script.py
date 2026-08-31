"""Non-executing source policy for the local verification script."""

from __future__ import annotations

import argparse
import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterable, Sequence


VERIFICATION_SCRIPT_PATH = "scripts/verify"
EXPECTED_COMMAND_SPECS = (
    ("Architecture policies", ("{python}", "-m", "architecture_checks", ".")),
    ("Django system check", ("{python}", "manage.py", "check")),
    (
        "Django migration drift check",
        ("{python}", "manage.py", "makemigrations", "--check", "--dry-run"),
    ),
    ("Django test suite", ("{python}", "manage.py", "test", "-v", "1")),
    (
        "Python compile check",
        (
            "{python}",
            "-m",
            "compileall",
            "anonymous_reporting",
            "architecture_checks",
            "reporter_gateway",
            "report_lifecycle",
            "security_interfaces",
            "submission_workflow",
            "tests",
        ),
    ),
    ("Manifest validation", ("sha256sum", "-c", "MANIFEST.sha256")),
)
EXPECTED_VERIFY_SCRIPT_AST_DIGEST = (
    "9ebfa245166eb8c6666496a9d2aa8ff90c0b5e0fadfc18eb4f1fb282b1067f04"
)


class VerificationScriptViolationCode(StrEnum):
    AST_DIGEST_MISMATCH = "AST_DIGEST_MISMATCH"
    COMMAND_PROFILE_MISMATCH = "COMMAND_PROFILE_MISMATCH"
    PATH_OUT_OF_ROOT = "PATH_OUT_OF_ROOT"
    SOURCE_MALFORMED = "SOURCE_MALFORMED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class VerificationScriptViolation:
    code: VerificationScriptViolationCode
    relative_path: str
    detail_code: str


def _violation(
    code: VerificationScriptViolationCode,
    relative_path: str,
    detail_code: str,
) -> VerificationScriptViolation:
    return VerificationScriptViolation(
        code=code,
        relative_path=relative_path,
        detail_code=detail_code,
    )


def _sorted(
    violations: Iterable[VerificationScriptViolation],
) -> tuple[VerificationScriptViolation, ...]:
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


def _ast_digest(tree: ast.AST) -> str:
    payload = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _literal_command_specs(
    tree: ast.AST,
) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    for node in tree.body if isinstance(tree, ast.Module) else ():
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "COMMAND_SPECS"
            for target in node.targets
        ):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (SyntaxError, ValueError):
            return None
        if not isinstance(value, tuple):
            return None
        return value
    return None


def analyze_verification_script_source(
    source: str,
) -> tuple[VerificationScriptViolation, ...]:
    """Validate the verification script without importing or executing it."""

    try:
        tree = ast.parse(source, filename=VERIFICATION_SCRIPT_PATH)
    except SyntaxError:
        return (
            _violation(
                VerificationScriptViolationCode.SOURCE_MALFORMED,
                VERIFICATION_SCRIPT_PATH,
                "PYTHON_SYNTAX",
            ),
        )

    violations: list[VerificationScriptViolation] = []
    if _literal_command_specs(tree) != EXPECTED_COMMAND_SPECS:
        violations.append(
            _violation(
                VerificationScriptViolationCode.COMMAND_PROFILE_MISMATCH,
                VERIFICATION_SCRIPT_PATH,
                "REVIEWED_SEQUENCE_REQUIRED",
            )
        )
    if _ast_digest(tree) != EXPECTED_VERIFY_SCRIPT_AST_DIGEST:
        violations.append(
            _violation(
                VerificationScriptViolationCode.AST_DIGEST_MISMATCH,
                VERIFICATION_SCRIPT_PATH,
                "REVIEWED_AST_REQUIRED",
            )
        )
    return _sorted(violations)


def scan_verification_script_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[VerificationScriptViolation, ...]:
    """Read and analyze only the reviewed verification script path."""

    root = relative_to.resolve()
    resolved_path = path.resolve()
    if not resolved_path.is_relative_to(root):
        return (
            _violation(
                VerificationScriptViolationCode.PATH_OUT_OF_ROOT,
                VERIFICATION_SCRIPT_PATH,
                "PATH_PROFILE",
            ),
        )
    try:
        source = resolved_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (
            _violation(
                VerificationScriptViolationCode.SOURCE_UNAVAILABLE,
                VERIFICATION_SCRIPT_PATH,
                "READ_FAILED",
            ),
        )
    return analyze_verification_script_source(source)


def scan_repository_verification_script(
    root: Path,
) -> tuple[VerificationScriptViolation, ...]:
    """Run the non-executing verification-script source policy."""

    return scan_verification_script_source(
        path=root / VERIFICATION_SCRIPT_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the local verification script source profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_verification_script(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
