"""Content-free source policy for the GitHub Actions CI workflow."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterable, Sequence


CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_CI_WORKFLOW_SHA256 = (
    "eba1892a57c2b23d4be823cd72b0305193bed328e301f5b8c3fc8c9f548b8d8a"
)
REQUIRED_WORKFLOW_LINES = (
    "name: CI",
    "    branches: [main, alpha-direct]",
    "  contents: read",
    "  test:",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 15",
    (
        "        uses: actions/checkout@"
        "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
    ),
    (
        "        uses: actions/setup-python@"
        "5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"
    ),
    '          python-version: "3.13"',
    "          cache: pip",
    "          cache-dependency-path: requirements.lock",
    "      - name: Install locked dependencies",
    "        run: python -m pip install --require-hashes -r requirements.lock",
    "      - name: Run reviewed verification script",
    "        run: scripts/verify",
    "      - name: Run PostgreSQL verification in Docker",
    "        run: scripts/docker-local test",
)
FORBIDDEN_WORKFLOW_FRAGMENTS = (
    "pull_request_target",
    "contents: write",
    "id-token: write",
    "actions/checkout@main",
    "actions/checkout@master",
    "actions/setup-python@main",
    "actions/setup-python@master",
    "pip install -r requirements",
    "pip install -r requirements.in",
    "pip install --upgrade",
    "continue-on-error: true",
)


class CIWorkflowViolationCode(StrEnum):
    FORBIDDEN_WORKFLOW_FRAGMENT = "FORBIDDEN_WORKFLOW_FRAGMENT"
    PATH_OUT_OF_ROOT = "PATH_OUT_OF_ROOT"
    REQUIRED_WORKFLOW_LINE_MISSING = "REQUIRED_WORKFLOW_LINE_MISSING"
    SOURCE_HASH_MISMATCH = "SOURCE_HASH_MISMATCH"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class CIWorkflowViolation:
    code: CIWorkflowViolationCode
    relative_path: str
    detail_code: str


def _violation(
    code: CIWorkflowViolationCode,
    relative_path: str,
    detail_code: str,
) -> CIWorkflowViolation:
    return CIWorkflowViolation(
        code=code,
        relative_path=relative_path,
        detail_code=detail_code,
    )


def _sorted(
    violations: Iterable[CIWorkflowViolation],
) -> tuple[CIWorkflowViolation, ...]:
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


def _detail_from_required_line(line: str) -> str:
    return (
        line.strip()
        .upper()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("-", "_")
        .replace(".", "_")
        .replace(":", "")
        .replace('"', "")
        .replace("#", "")
    )[:80]


def _detail_from_forbidden_fragment(fragment: str) -> str:
    return (
        fragment.upper()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("-", "_")
        .replace(".", "_")
        .replace(":", "")
    )[:80]


def analyze_ci_workflow_source(
    source: str,
) -> tuple[CIWorkflowViolation, ...]:
    """Validate the reviewed CI workflow without executing it."""

    violations: list[CIWorkflowViolation] = []
    source_lines = tuple(source.splitlines())
    for required_line in REQUIRED_WORKFLOW_LINES:
        if required_line not in source_lines:
            violations.append(
                _violation(
                    CIWorkflowViolationCode.REQUIRED_WORKFLOW_LINE_MISSING,
                    CI_WORKFLOW_PATH,
                    _detail_from_required_line(required_line),
                )
            )
    for forbidden_fragment in FORBIDDEN_WORKFLOW_FRAGMENTS:
        if forbidden_fragment in source:
            violations.append(
                _violation(
                    CIWorkflowViolationCode.FORBIDDEN_WORKFLOW_FRAGMENT,
                    CI_WORKFLOW_PATH,
                    _detail_from_forbidden_fragment(forbidden_fragment),
                )
            )

    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if digest != EXPECTED_CI_WORKFLOW_SHA256:
        violations.append(
            _violation(
                CIWorkflowViolationCode.SOURCE_HASH_MISMATCH,
                CI_WORKFLOW_PATH,
                "REVIEWED_WORKFLOW_REQUIRED",
            )
        )
    return _sorted(violations)


def scan_ci_workflow_source(
    *,
    path: Path,
    relative_to: Path,
) -> tuple[CIWorkflowViolation, ...]:
    """Read and analyze only the reviewed CI workflow path."""

    root = relative_to.resolve()
    resolved_path = path.resolve()
    if not resolved_path.is_relative_to(root):
        return (
            _violation(
                CIWorkflowViolationCode.PATH_OUT_OF_ROOT,
                CI_WORKFLOW_PATH,
                "PATH_PROFILE",
            ),
        )
    try:
        source = resolved_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (
            _violation(
                CIWorkflowViolationCode.SOURCE_UNAVAILABLE,
                CI_WORKFLOW_PATH,
                "READ_FAILED",
            ),
        )
    return analyze_ci_workflow_source(source)


def scan_repository_ci_workflow(
    root: Path,
) -> tuple[CIWorkflowViolation, ...]:
    """Run the non-executing CI workflow source policy."""

    return scan_ci_workflow_source(
        path=root / CI_WORKFLOW_PATH,
        relative_to=root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the reviewed GitHub Actions CI workflow profile."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = scan_repository_ci_workflow(args.root)
    for violation in violations:
        print(
            f"{violation.code.value} "
            f"{violation.relative_path} {violation.detail_code}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
