"""Aggregate non-executing architecture checks for the repository."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from .bootstrap import scan_bootstrap_sources
from .dependency_policy import scan_repository
from .descriptors import (
    ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH,
    ALERT_DESCRIPTOR_PATH,
    AUDIT_DESCRIPTOR_PATH,
    REPORT_STEP_UP_DESCRIPTOR_PATH,
    scan_administrative_step_up_descriptor_source,
    scan_alert_descriptor_source,
    scan_audit_descriptor_source,
    scan_report_step_up_descriptor_source,
)
from .imports import (
    REPORTER_GATEWAY_IMPORT_POLICY,
    REPORTER_ROOT_URL_IMPORT_POLICY,
    scan_python_file,
    scan_python_package,
)
from .initializers import scan_initializer_sources
from .lifecycle import scan_lifecycle_sources
from .migrations import (
    scan_lifecycle_migrations,
    scan_submission_migrations,
)
from .negative_capabilities import scan_negative_capability_sources
from .orchestration import scan_inert_orchestration_sources
from .repository_hygiene import scan_repository_hygiene
from .submission import scan_submission_sources
from .surfaces import (
    analyze_css_source,
    analyze_reporter_python_source,
    analyze_settings_source,
    analyze_template_source,
    analyze_urlconf_source,
    scan_surface_file,
)
from .verification_script import scan_repository_verification_script


class RawViolation(Protocol):
    code: object
    relative_path: str


@dataclass(frozen=True, slots=True)
class ArchitectureCheckViolation:
    check_name: str
    code: str
    relative_path: str
    line: int
    detail_code: str


@dataclass(frozen=True, slots=True)
class ArchitectureCheck:
    name: str
    scan: Callable[[Path], tuple[object, ...]]


def _code_name(value: object) -> str:
    code_value = getattr(value, "value", value)
    if type(code_value) is str:
        return code_value
    return type(value).__name__


def _detail_code(violation: object) -> str:
    detail = getattr(violation, "detail_code", None)
    if type(detail) is str:
        return detail
    module = getattr(violation, "module", None)
    if type(module) is str:
        return module
    return "NONE"


def _normalize(
    *,
    check_name: str,
    violations: Iterable[object],
) -> tuple[ArchitectureCheckViolation, ...]:
    normalized = []
    for violation in violations:
        normalized.append(
            ArchitectureCheckViolation(
                check_name=check_name,
                code=_code_name(getattr(violation, "code", object())),
                relative_path=getattr(
                    violation,
                    "relative_path",
                    "<unknown>",
                ),
                line=getattr(violation, "line", 0),
                detail_code=_detail_code(violation),
            )
        )
    return tuple(normalized)


def _root_url_imports(root: Path) -> tuple[object, ...]:
    return scan_python_file(
        path=root / "anonymous_reporting" / "urls.py",
        policy=REPORTER_ROOT_URL_IMPORT_POLICY,
        relative_to=root,
    )


def _reporter_gateway_imports(root: Path) -> tuple[object, ...]:
    return scan_python_package(
        package_root=root / "reporter_gateway",
        policy=REPORTER_GATEWAY_IMPORT_POLICY,
        relative_to=root,
    )


def _settings_surface(root: Path) -> tuple[object, ...]:
    return scan_surface_file(
        path=root / "anonymous_reporting" / "settings.py",
        relative_to=root,
        analyzer=analyze_settings_source,
    )


def _url_surface(root: Path) -> tuple[object, ...]:
    return scan_surface_file(
        path=root / "anonymous_reporting" / "urls.py",
        relative_to=root,
        analyzer=analyze_urlconf_source,
    )


def _reporter_view_surface(root: Path) -> tuple[object, ...]:
    return scan_surface_file(
        path=root / "reporter_gateway" / "views.py",
        relative_to=root,
        analyzer=analyze_reporter_python_source,
    )


def _reporter_header_surface(root: Path) -> tuple[object, ...]:
    return scan_surface_file(
        path=root / "reporter_gateway" / "middleware.py",
        relative_to=root,
        analyzer=analyze_reporter_python_source,
    )


def _template_surface(root: Path) -> tuple[object, ...]:
    return scan_surface_file(
        path=root / "templates" / "reporter_gateway" / "home.html",
        relative_to=root,
        analyzer=analyze_template_source,
    )


def _css_surface(root: Path) -> tuple[object, ...]:
    return scan_surface_file(
        path=root / "static" / "reporter_gateway" / "home.css",
        relative_to=root,
        analyzer=analyze_css_source,
    )


def _lifecycle_migrations(root: Path) -> tuple[object, ...]:
    return scan_lifecycle_migrations(
        migrations_root=root / "report_lifecycle" / "migrations",
        relative_to=root,
    )


def _submission_migrations(root: Path) -> tuple[object, ...]:
    return scan_submission_migrations(
        migrations_root=root / "submission_workflow" / "migrations",
        relative_to=root,
    )


def _bootstrap_sources(root: Path) -> tuple[object, ...]:
    return scan_bootstrap_sources(repository_root=root)


def _initializer_sources(root: Path) -> tuple[object, ...]:
    return scan_initializer_sources(repository_root=root)


def _submission_sources(root: Path) -> tuple[object, ...]:
    return scan_submission_sources(repository_root=root)


def _lifecycle_sources(root: Path) -> tuple[object, ...]:
    return scan_lifecycle_sources(repository_root=root)


def _orchestration_sources(root: Path) -> tuple[object, ...]:
    return scan_inert_orchestration_sources(
        lifecycle_root=root / "report_lifecycle",
        relative_to=root,
    )


def _negative_capabilities(root: Path) -> tuple[object, ...]:
    return scan_negative_capability_sources(root=root)


def _administrative_step_up_descriptor(root: Path) -> tuple[object, ...]:
    return scan_administrative_step_up_descriptor_source(
        path=root / ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH,
        relative_to=root,
    )


def _audit_descriptor(root: Path) -> tuple[object, ...]:
    return scan_audit_descriptor_source(
        path=root / AUDIT_DESCRIPTOR_PATH,
        relative_to=root,
    )


def _alert_descriptor(root: Path) -> tuple[object, ...]:
    return scan_alert_descriptor_source(
        path=root / ALERT_DESCRIPTOR_PATH,
        relative_to=root,
    )


def _report_step_up_descriptor(root: Path) -> tuple[object, ...]:
    return scan_report_step_up_descriptor_source(
        path=root / REPORT_STEP_UP_DESCRIPTOR_PATH,
        relative_to=root,
    )


ARCHITECTURE_CHECKS = (
    ArchitectureCheck("dependency-policy", scan_repository),
    ArchitectureCheck("repository-hygiene", scan_repository_hygiene),
    ArchitectureCheck("verification-script", scan_repository_verification_script),
    ArchitectureCheck("root-url-imports", _root_url_imports),
    ArchitectureCheck("reporter-gateway-imports", _reporter_gateway_imports),
    ArchitectureCheck("settings-surface", _settings_surface),
    ArchitectureCheck("url-surface", _url_surface),
    ArchitectureCheck("reporter-view-surface", _reporter_view_surface),
    ArchitectureCheck("reporter-header-surface", _reporter_header_surface),
    ArchitectureCheck("template-surface", _template_surface),
    ArchitectureCheck("css-surface", _css_surface),
    ArchitectureCheck("lifecycle-migrations", _lifecycle_migrations),
    ArchitectureCheck("submission-migrations", _submission_migrations),
    ArchitectureCheck("bootstrap-sources", _bootstrap_sources),
    ArchitectureCheck("initializer-sources", _initializer_sources),
    ArchitectureCheck("submission-sources", _submission_sources),
    ArchitectureCheck("lifecycle-sources", _lifecycle_sources),
    ArchitectureCheck("orchestration-sources", _orchestration_sources),
    ArchitectureCheck("negative-capabilities", _negative_capabilities),
    ArchitectureCheck(
        "administrative-step-up-descriptor",
        _administrative_step_up_descriptor,
    ),
    ArchitectureCheck("audit-descriptor", _audit_descriptor),
    ArchitectureCheck("alert-descriptor", _alert_descriptor),
    ArchitectureCheck("report-step-up-descriptor", _report_step_up_descriptor),
)


def run_architecture_checks(
    *, repository_root: Path
) -> tuple[ArchitectureCheckViolation, ...]:
    """Run every static policy and return normalized content-free violations."""

    root = repository_root.resolve()
    violations: list[ArchitectureCheckViolation] = []
    for check in ARCHITECTURE_CHECKS:
        violations.extend(
            _normalize(
                check_name=check.name,
                violations=check.scan(root),
            )
        )
    return tuple(
        sorted(
            violations,
            key=lambda item: (
                item.check_name,
                item.relative_path,
                item.line,
                item.code,
                item.detail_code,
            ),
        )
    )


def format_violation(violation: ArchitectureCheckViolation) -> str:
    return (
        f"{violation.check_name} {violation.code} "
        f"{violation.relative_path}:{violation.line} "
        f"{violation.detail_code}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run every static HavenSignal architecture policy."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    violations = run_architecture_checks(repository_root=args.root)
    for violation in violations:
        print(format_violation(violation))
    if violations:
        return 1
    print("architecture checks passed")
    return 0
