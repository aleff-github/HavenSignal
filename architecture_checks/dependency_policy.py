"""Fail-closed checks for the repository dependency update policy."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


APPROVED_DJANGO_SERIES = (5, 2)
EXPECTED_DEPENDABOT_ECOSYSTEMS = frozenset({"pip", "github-actions"})
MANIFEST_PATH = "MANIFEST.sha256"


class DependencyPolicyViolationCode(StrEnum):
    DEPENDABOT_ECOSYSTEM_INVALID = "DEPENDABOT_ECOSYSTEM_INVALID"
    DEPENDABOT_VERSION_UPDATES_ENABLED = "DEPENDABOT_VERSION_UPDATES_ENABLED"
    DJANGO_DECLARATION_INVALID = "DJANGO_DECLARATION_INVALID"
    DJANGO_LOCK_INVALID = "DJANGO_LOCK_INVALID"
    DJANGO_LOCK_MISMATCH = "DJANGO_LOCK_MISMATCH"
    DJANGO_SERIES_UNAPPROVED = "DJANGO_SERIES_UNAPPROVED"
    MANIFEST_COVERAGE_MISMATCH = "MANIFEST_COVERAGE_MISMATCH"
    MANIFEST_FILE_MISSING = "MANIFEST_FILE_MISSING"
    MANIFEST_FORMAT_INVALID = "MANIFEST_FORMAT_INVALID"
    MANIFEST_HASH_MISMATCH = "MANIFEST_HASH_MISMATCH"
    POLICY_INPUT_UNAVAILABLE = "POLICY_INPUT_UNAVAILABLE"
    TRACKED_FILES_UNAVAILABLE = "TRACKED_FILES_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class DependencyPolicyViolation:
    code: DependencyPolicyViolationCode
    relative_path: str
    detail_code: str


_DEPENDABOT_ECOSYSTEM_LINE = re.compile(
    r"^  - package-ecosystem:\s*(?:['\"])?([^'\"\s]+)(?:['\"])?\s*$"
)
_DEPENDABOT_LIMIT_LINE = re.compile(
    r"^\s{4}open-pull-requests-limit:\s*([^\s#]+)"
)
_DECLARED_DJANGO = re.compile(
    r"^\s*django\s*==\s*(\d+)\.(\d+)\.(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_LOCKED_DJANGO = re.compile(
    r"^\s*django\s*==\s*(\d+)\.(\d+)\.(\d+)\s*(?:\\)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def _violation(
    code: DependencyPolicyViolationCode,
    relative_path: str,
    detail_code: str,
) -> DependencyPolicyViolation:
    return DependencyPolicyViolation(
        code=code,
        relative_path=relative_path,
        detail_code=detail_code,
    )


def _sorted(
    violations: Iterable[DependencyPolicyViolation],
) -> tuple[DependencyPolicyViolation, ...]:
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


def analyze_dependabot_source(
    source: str,
) -> tuple[DependencyPolicyViolation, ...]:
    """Require routine version updates to be disabled for each ecosystem."""

    blocks: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in source.splitlines():
        match = _DEPENDABOT_ECOSYSTEM_LINE.match(line)
        if match:
            current = (match.group(1), [])
            blocks.append(current)
        elif current is not None:
            current[1].append(line)

    violations: list[DependencyPolicyViolation] = []
    configured_ecosystems = {name for name, _ in blocks}
    for ecosystem in sorted(
        configured_ecosystems | EXPECTED_DEPENDABOT_ECOSYSTEMS
    ):
        matching = [lines for name, lines in blocks if name == ecosystem]
        if len(matching) != 1:
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.DEPENDABOT_ECOSYSTEM_INVALID,
                    ".github/dependabot.yml",
                    ecosystem.upper().replace("-", "_"),
                )
            )
            continue
        limits = [
            match.group(1)
            for line in matching[0]
            if (match := _DEPENDABOT_LIMIT_LINE.match(line))
        ]
        if limits != ["0"]:
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.DEPENDABOT_VERSION_UPDATES_ENABLED,
                    ".github/dependabot.yml",
                    ecosystem.upper().replace("-", "_"),
                )
            )
    return _sorted(violations)


def _single_version(
    source: str,
    pattern: re.Pattern[str],
) -> tuple[int, int, int] | None:
    matches = pattern.findall(source)
    if len(matches) != 1:
        return None
    return tuple(int(component) for component in matches[0])


def analyze_django_sources(
    *, declared_source: str, locked_source: str
) -> tuple[DependencyPolicyViolation, ...]:
    """Require one exact Django pin on the approved LTS line in both files."""

    declared = _single_version(declared_source, _DECLARED_DJANGO)
    locked = _single_version(locked_source, _LOCKED_DJANGO)
    violations: list[DependencyPolicyViolation] = []
    if declared is None:
        violations.append(
            _violation(
                DependencyPolicyViolationCode.DJANGO_DECLARATION_INVALID,
                "requirements.in",
                "EXACT_PIN_REQUIRED",
            )
        )
    elif declared[:2] != APPROVED_DJANGO_SERIES:
        violations.append(
            _violation(
                DependencyPolicyViolationCode.DJANGO_SERIES_UNAPPROVED,
                "requirements.in",
                "APPROVED_LTS_SERIES_REQUIRED",
            )
        )
    if locked is None:
        violations.append(
            _violation(
                DependencyPolicyViolationCode.DJANGO_LOCK_INVALID,
                "requirements.lock",
                "EXACT_LOCK_REQUIRED",
            )
        )
    elif locked[:2] != APPROVED_DJANGO_SERIES:
        violations.append(
            _violation(
                DependencyPolicyViolationCode.DJANGO_SERIES_UNAPPROVED,
                "requirements.lock",
                "APPROVED_LTS_SERIES_REQUIRED",
            )
        )
    if declared is not None and locked is not None and declared != locked:
        violations.append(
            _violation(
                DependencyPolicyViolationCode.DJANGO_LOCK_MISMATCH,
                "requirements.lock",
                "DECLARATION_AND_LOCK_MUST_MATCH",
            )
        )
    return _sorted(violations)


def _safe_manifest_path(relative_path: str) -> PurePosixPath | None:
    path = PurePosixPath(relative_path)
    if (
        "\\" in relative_path
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
        or relative_path == MANIFEST_PATH
    ):
        return None
    return path


def analyze_manifest(
    *, root: Path, source: str, tracked_paths: Sequence[str]
) -> tuple[DependencyPolicyViolation, ...]:
    """Verify manifest syntax, coverage, file presence, and SHA-256 hashes."""

    entries: dict[str, str] = {}
    violations: list[DependencyPolicyViolation] = []
    for line in source.splitlines():
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.MANIFEST_FORMAT_INVALID,
                    MANIFEST_PATH,
                    "LINE_FORMAT",
                )
            )
            continue
        digest, relative_path = match.groups()
        if (
            relative_path in entries
            or _safe_manifest_path(relative_path) is None
        ):
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.MANIFEST_FORMAT_INVALID,
                    MANIFEST_PATH,
                    "PATH_PROFILE",
                )
            )
            continue
        entries[relative_path] = digest

    expected_paths = set(tracked_paths) - {MANIFEST_PATH}
    if set(entries) != expected_paths:
        violations.append(
            _violation(
                DependencyPolicyViolationCode.MANIFEST_COVERAGE_MISMATCH,
                MANIFEST_PATH,
                "TRACKED_PATH_SET",
            )
        )

    for relative_path, expected_digest in entries.items():
        safe_path = _safe_manifest_path(relative_path)
        if safe_path is None:
            continue
        target = root.joinpath(*safe_path.parts).resolve()
        if not target.is_relative_to(root):
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.MANIFEST_FORMAT_INVALID,
                    MANIFEST_PATH,
                    "PATH_PROFILE",
                )
            )
            continue
        try:
            payload = target.read_bytes()
        except OSError:
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.MANIFEST_FILE_MISSING,
                    relative_path,
                    "TRACKED_FILE_UNAVAILABLE",
                )
            )
            continue
        actual_digest = hashlib.sha256(payload).hexdigest()
        if actual_digest != expected_digest:
            violations.append(
                _violation(
                    DependencyPolicyViolationCode.MANIFEST_HASH_MISMATCH,
                    relative_path,
                    "SHA256_MISMATCH",
                )
            )
    return _sorted(violations)


def _read_policy_source(
    root: Path, relative_path: str
) -> tuple[str | None, DependencyPolicyViolation | None]:
    try:
        return (root / relative_path).read_text(encoding="utf-8"), None
    except (OSError, UnicodeError):
        return None, _violation(
            DependencyPolicyViolationCode.POLICY_INPUT_UNAVAILABLE,
            relative_path,
            "READ_FAILED",
        )


def _tracked_paths(
    root: Path,
) -> tuple[tuple[str, ...] | None, DependencyPolicyViolation | None]:
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
            DependencyPolicyViolationCode.TRACKED_FILES_UNAVAILABLE,
            "<repository>",
            "GIT_LS_FILES_FAILED",
        )
    return paths, None


def scan_repository(root: Path) -> tuple[DependencyPolicyViolation, ...]:
    """Run every dependency-policy check against a repository checkout."""

    root = root.resolve()
    sources: dict[str, str] = {}
    violations: list[DependencyPolicyViolation] = []
    for relative_path in (
        ".github/dependabot.yml",
        "requirements.in",
        "requirements.lock",
        MANIFEST_PATH,
    ):
        source, violation = _read_policy_source(root, relative_path)
        if violation is not None:
            violations.append(violation)
        elif source is not None:
            sources[relative_path] = source

    dependabot_source = sources.get(".github/dependabot.yml")
    if dependabot_source is not None:
        violations.extend(analyze_dependabot_source(dependabot_source))
    declared_source = sources.get("requirements.in")
    locked_source = sources.get("requirements.lock")
    if declared_source is not None and locked_source is not None:
        violations.extend(
            analyze_django_sources(
                declared_source=declared_source,
                locked_source=locked_source,
            )
        )
    manifest_source = sources.get(MANIFEST_PATH)
    if manifest_source is not None:
        tracked_paths, tracked_violation = _tracked_paths(root)
        if tracked_violation is not None:
            violations.append(tracked_violation)
        elif tracked_paths is not None:
            violations.extend(
                analyze_manifest(
                    root=root,
                    source=manifest_source,
                    tracked_paths=tracked_paths,
                )
            )
    return _sorted(violations)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the fail-closed dependency security policy."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
