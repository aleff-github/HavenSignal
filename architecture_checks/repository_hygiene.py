"""Content-free repository hygiene checks for local-sensitive artifacts."""

from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


GITIGNORE_PATH = ".gitignore"
ALLOWED_TRACKED_PATH_EXCEPTIONS = frozenset({".env.example"})
FORBIDDEN_TRACKED_PATH_PATTERNS = (
    ("*.sqlite3", "LOCAL_DATABASE"),
    ("*.log", "LOCAL_LOG"),
    (".coverage", "LOCAL_TEST_ARTIFACT"),
    ("htmlcov/*", "LOCAL_TEST_ARTIFACT"),
    (".pytest_cache/*", "LOCAL_TEST_ARTIFACT"),
    (".mypy_cache/*", "LOCAL_TEST_ARTIFACT"),
    (".ruff_cache/*", "LOCAL_TEST_ARTIFACT"),
    ("__pycache__/*", "PYTHON_CACHE"),
    ("*/__pycache__/*", "PYTHON_CACHE"),
    ("*.pyc", "PYTHON_CACHE"),
    ("*.pyo", "PYTHON_CACHE"),
    (".venv/*", "VIRTUAL_ENVIRONMENT"),
    ("venv/*", "VIRTUAL_ENVIRONMENT"),
    ("env/*", "VIRTUAL_ENVIRONMENT"),
    ("media/*", "USER_MEDIA"),
    ("staticfiles/*", "COLLECTED_STATIC"),
    (".env", "LOCAL_ENVIRONMENT"),
    (".env.*", "LOCAL_ENVIRONMENT"),
    ("secrets/*", "SECRET_DIRECTORY"),
    ("*.pem", "SECRET_MATERIAL"),
    ("*.key", "SECRET_MATERIAL"),
    ("*.p12", "SECRET_MATERIAL"),
    ("*.pfx", "SECRET_MATERIAL"),
    ("exports/*", "EXPORT_ARTIFACT"),
    ("tmp/*", "TEMPORARY_WORKSPACE"),
    ("temp/*", "TEMPORARY_WORKSPACE"),
    ("quarantine/*", "TEMPORARY_WORKSPACE"),
)
REQUIRED_GITIGNORE_RULES = frozenset(
    {
        "*.sqlite3",
        "*.log",
        ".coverage",
        "htmlcov/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        "__pycache__/",
        "*.py[cod]",
        "*.pyo",
        ".venv/",
        "venv/",
        "env/",
        "media/",
        "staticfiles/",
        ".env",
        ".env.*",
        "!.env.example",
        "secrets/",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "exports/",
        "tmp/",
        "temp/",
        "quarantine/",
    }
)


class RepositoryHygieneViolationCode(StrEnum):
    FORBIDDEN_TRACKED_PATH = "FORBIDDEN_TRACKED_PATH"
    GITIGNORE_RULE_MISSING = "GITIGNORE_RULE_MISSING"
    POLICY_INPUT_UNAVAILABLE = "POLICY_INPUT_UNAVAILABLE"
    TRACKED_FILES_UNAVAILABLE = "TRACKED_FILES_UNAVAILABLE"
    TRACKED_PATH_INVALID = "TRACKED_PATH_INVALID"


@dataclass(frozen=True, slots=True)
class RepositoryHygieneViolation:
    code: RepositoryHygieneViolationCode
    relative_path: str
    detail_code: str


def _violation(
    code: RepositoryHygieneViolationCode,
    relative_path: str,
    detail_code: str,
) -> RepositoryHygieneViolation:
    return RepositoryHygieneViolation(
        code=code,
        relative_path=relative_path,
        detail_code=detail_code,
    )


def _sorted(
    violations: Iterable[RepositoryHygieneViolation],
) -> tuple[RepositoryHygieneViolation, ...]:
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


def _safe_relative_path(relative_path: str) -> PurePosixPath | None:
    path = PurePosixPath(relative_path)
    if (
        "\\" in relative_path
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
    ):
        return None
    return path


def _matches_forbidden_pattern(relative_path: str) -> str | None:
    if relative_path in ALLOWED_TRACKED_PATH_EXCEPTIONS:
        return None
    for pattern, detail_code in FORBIDDEN_TRACKED_PATH_PATTERNS:
        if fnmatchcase(relative_path, pattern):
            return detail_code
    return None


def analyze_tracked_paths(
    tracked_paths: Sequence[str],
) -> tuple[RepositoryHygieneViolation, ...]:
    """Reject tracked local-sensitive artifacts without reading file contents."""

    violations: list[RepositoryHygieneViolation] = []
    for relative_path in tracked_paths:
        if _safe_relative_path(relative_path) is None:
            violations.append(
                _violation(
                    RepositoryHygieneViolationCode.TRACKED_PATH_INVALID,
                    "<repository>",
                    "PATH_PROFILE",
                )
            )
            continue
        detail_code = _matches_forbidden_pattern(relative_path)
        if detail_code is not None:
            violations.append(
                _violation(
                    RepositoryHygieneViolationCode.FORBIDDEN_TRACKED_PATH,
                    relative_path,
                    detail_code,
                )
            )
    return _sorted(violations)


def analyze_gitignore_source(
    source: str,
) -> tuple[RepositoryHygieneViolation, ...]:
    """Require baseline ignore rules for local artifacts and secret material."""

    configured_rules = {
        line.strip()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    violations = [
        _violation(
            RepositoryHygieneViolationCode.GITIGNORE_RULE_MISSING,
            GITIGNORE_PATH,
            rule.upper().replace("*", "STAR").replace(".", "DOT").replace("/", "_"),
        )
        for rule in REQUIRED_GITIGNORE_RULES - configured_rules
    ]
    return _sorted(violations)


def _read_gitignore(
    root: Path,
) -> tuple[str | None, RepositoryHygieneViolation | None]:
    try:
        return (root / GITIGNORE_PATH).read_text(encoding="utf-8"), None
    except (OSError, UnicodeError):
        return None, _violation(
            RepositoryHygieneViolationCode.POLICY_INPUT_UNAVAILABLE,
            GITIGNORE_PATH,
            "READ_FAILED",
        )


def _tracked_paths(
    root: Path,
) -> tuple[tuple[str, ...] | None, RepositoryHygieneViolation | None]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        paths = tuple(
            item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None, _violation(
            RepositoryHygieneViolationCode.TRACKED_FILES_UNAVAILABLE,
            "<repository>",
            "GIT_LS_FILES_FAILED",
        )
    return paths, None


def scan_repository_hygiene(
    root: Path,
) -> tuple[RepositoryHygieneViolation, ...]:
    """Run content-free repository hygiene checks against a checkout."""

    root = root.resolve()
    violations: list[RepositoryHygieneViolation] = []
    gitignore_source, gitignore_violation = _read_gitignore(root)
    if gitignore_violation is not None:
        violations.append(gitignore_violation)
    elif gitignore_source is not None:
        violations.extend(analyze_gitignore_source(gitignore_source))

    tracked_paths, tracked_violation = _tracked_paths(root)
    if tracked_violation is not None:
        violations.append(tracked_violation)
    elif tracked_paths is not None:
        violations.extend(analyze_tracked_paths(tracked_paths))
    return _sorted(violations)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify content-free repository hygiene rules."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_hygiene(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
