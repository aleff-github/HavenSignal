"""AST-based import allowlists for currently inert Django surfaces."""

import ast
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ImportViolationCode(StrEnum):
    DISALLOWED_ABSOLUTE_IMPORT = "DISALLOWED_ABSOLUTE_IMPORT"
    DYNAMIC_CODE_EXECUTION = "DYNAMIC_CODE_EXECUTION"
    DYNAMIC_IMPORT = "DYNAMIC_IMPORT"
    PARENT_RELATIVE_IMPORT = "PARENT_RELATIVE_IMPORT"
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    STAR_IMPORT = "STAR_IMPORT"


@dataclass(frozen=True, slots=True)
class ImportPolicy:
    name: str
    allowed_absolute_modules: frozenset[str]
    allow_local_relative_imports: bool


@dataclass(frozen=True, slots=True)
class ArchitectureImportViolation:
    code: ImportViolationCode
    relative_path: str
    line: int
    module: str | None


REPORTER_GATEWAY_IMPORT_POLICY = ImportPolicy(
    name="REPORTER_GATEWAY_INERT_V1",
    allowed_absolute_modules=frozenset(
        {
            "collections.abc",
            "django.http",
            "django.shortcuts",
            "django.views.decorators.http",
        }
    ),
    allow_local_relative_imports=True,
)


REPORTER_ROOT_URL_IMPORT_POLICY = ImportPolicy(
    name="REPORTER_ROOT_URL_INERT_V1",
    allowed_absolute_modules=frozenset(
        {
            "django.urls",
            "reporter_gateway.views",
        }
    ),
    allow_local_relative_imports=False,
)


def _violation(
    *,
    code: ImportViolationCode,
    relative_path: str,
    line: int,
    module: str | None,
) -> ArchitectureImportViolation:
    return ArchitectureImportViolation(
        code=code,
        relative_path=relative_path,
        line=line,
        module=module,
    )


def _analyze_import(
    node: ast.Import,
    *,
    relative_path: str,
    policy: ImportPolicy,
) -> list[ArchitectureImportViolation]:
    return [
        _violation(
            code=ImportViolationCode.DISALLOWED_ABSOLUTE_IMPORT,
            relative_path=relative_path,
            line=node.lineno,
            module=alias.name,
        )
        for alias in node.names
        if alias.name not in policy.allowed_absolute_modules
    ]


def _analyze_import_from(
    node: ast.ImportFrom,
    *,
    relative_path: str,
    policy: ImportPolicy,
) -> list[ArchitectureImportViolation]:
    violations: list[ArchitectureImportViolation] = []
    module = node.module
    if any(alias.name == "*" for alias in node.names):
        violations.append(
            _violation(
                code=ImportViolationCode.STAR_IMPORT,
                relative_path=relative_path,
                line=node.lineno,
                module=module,
            )
        )

    if node.level == 1 and policy.allow_local_relative_imports:
        return violations
    if node.level > 0:
        violations.append(
            _violation(
                code=ImportViolationCode.PARENT_RELATIVE_IMPORT,
                relative_path=relative_path,
                line=node.lineno,
                module=module,
            )
        )
        return violations
    if module not in policy.allowed_absolute_modules:
        violations.append(
            _violation(
                code=ImportViolationCode.DISALLOWED_ABSOLUTE_IMPORT,
                relative_path=relative_path,
                line=node.lineno,
                module=module,
            )
        )
    return violations


def _dangerous_call(node: ast.Call) -> tuple[ImportViolationCode, str] | None:
    if isinstance(node.func, ast.Name):
        if node.func.id == "__import__":
            return ImportViolationCode.DYNAMIC_IMPORT, "__import__"
        if node.func.id in {"eval", "exec"}:
            return ImportViolationCode.DYNAMIC_CODE_EXECUTION, node.func.id
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "builtins"
    ):
        if node.func.attr == "__import__":
            return ImportViolationCode.DYNAMIC_IMPORT, "builtins.__import__"
        if node.func.attr in {"eval", "exec"}:
            return (
                ImportViolationCode.DYNAMIC_CODE_EXECUTION,
                f"builtins.{node.func.attr}",
            )
    return None


def analyze_python_source(
    *,
    source: str,
    relative_path: str,
    policy: ImportPolicy,
) -> tuple[ArchitectureImportViolation, ...]:
    """Return controlled violations without importing or executing source."""

    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=ImportViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                module=None,
            ),
        )

    violations: list[ArchitectureImportViolation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            violations.extend(
                _analyze_import(
                    node,
                    relative_path=relative_path,
                    policy=policy,
                )
            )
        elif isinstance(node, ast.ImportFrom):
            violations.extend(
                _analyze_import_from(
                    node,
                    relative_path=relative_path,
                    policy=policy,
                )
            )
        elif isinstance(node, ast.Call):
            dangerous = _dangerous_call(node)
            if dangerous is not None:
                code, module = dangerous
                violations.append(
                    _violation(
                        code=code,
                        relative_path=relative_path,
                        line=node.lineno,
                        module=module,
                    )
                )
    return tuple(
        sorted(
            violations,
            key=lambda item: (
                item.relative_path,
                item.line,
                item.code.value,
                item.module or "",
            ),
        )
    )


def scan_python_file(
    *,
    path: Path,
    policy: ImportPolicy,
    relative_to: Path,
) -> tuple[ArchitectureImportViolation, ...]:
    try:
        resolved_root = relative_to.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
        relative_path = path.relative_to(relative_to).as_posix()
    except (OSError, ValueError):
        return (
            _violation(
                code=ImportViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-scan-path>",
                line=0,
                module=None,
            ),
        )
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (
            _violation(
                code=ImportViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                module=None,
            ),
        )
    return analyze_python_source(
        source=source,
        relative_path=relative_path,
        policy=policy,
    )


def scan_python_package(
    *,
    package_root: Path,
    policy: ImportPolicy,
    relative_to: Path,
) -> tuple[ArchitectureImportViolation, ...]:
    try:
        resolved_root = relative_to.resolve(strict=True)
        resolved_package = package_root.resolve(strict=True)
        resolved_package.relative_to(resolved_root)
        package_relative_path = package_root.relative_to(relative_to).as_posix()
    except (OSError, ValueError):
        return (
            _violation(
                code=ImportViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-package-path>",
                line=0,
                module=None,
            ),
        )
    if not resolved_package.is_dir():
        return (
            _violation(
                code=ImportViolationCode.SOURCE_PARSE_ERROR,
                relative_path=package_relative_path,
                line=0,
                module=None,
            ),
        )

    python_files = tuple(sorted(package_root.rglob("*.py")))
    if not python_files:
        return (
            _violation(
                code=ImportViolationCode.SOURCE_PARSE_ERROR,
                relative_path=package_relative_path,
                line=0,
                module=None,
            ),
        )

    violations: list[ArchitectureImportViolation] = []
    for path in python_files:
        violations.extend(
            scan_python_file(
                path=path,
                policy=policy,
                relative_to=relative_to,
            )
        )
    return tuple(violations)
