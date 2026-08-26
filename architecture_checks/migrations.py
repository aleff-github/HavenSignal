"""Non-executing policy for the inert report-lifecycle migration graph."""

import ast
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class MigrationViolationCode(StrEnum):
    FIELD_PROFILE_MISMATCH = "FIELD_PROFILE_MISMATCH"
    MIGRATION_GRAPH_MISMATCH = "MIGRATION_GRAPH_MISMATCH"
    MODEL_PROFILE_MISMATCH = "MODEL_PROFILE_MISMATCH"
    OPERATION_DISALLOWED = "OPERATION_DISALLOWED"
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"


@dataclass(frozen=True, slots=True)
class MigrationViolation:
    code: MigrationViolationCode
    relative_path: str
    line: int
    detail_code: str


EXPECTED_LIFECYCLE_MIGRATION_FIELDS = MappingProxyType(
    {
        "Report": (
            "id",
            "state",
            "state_version",
            "current_lease_generation",
            "active_operator_id",
            "received_at",
            "claimed_at",
            "claim_expires_at",
            "response_available_at",
            "terminal_at",
        ),
        "ReportLease": (
            "id",
            "operator_id",
            "generation",
            "state",
            "state_version",
            "opened_at",
            "last_activity_at",
            "absolute_expires_at",
            "closed_at",
            "report",
        ),
        "SecurityOperation": (
            "id",
            "kind",
            "state",
            "state_version",
            "bound_report_version",
            "fence_token",
            "idempotency_id",
            "actor_id",
            "lease_generation",
            "created_at",
            "activated_at",
            "terminal_at",
            "lease",
            "report",
        ),
    }
)

_EXPECTED_FIELD_TYPE_PROFILE = {
    "Report": (
        "UUIDField",
        "CharField",
        "PositiveBigIntegerField",
        "PositiveBigIntegerField",
        "UUIDField",
        "DateTimeField",
        "DateTimeField",
        "DateTimeField",
        "DateTimeField",
        "DateTimeField",
    ),
    "ReportLease": (
        "UUIDField",
        "UUIDField",
        "PositiveBigIntegerField",
        "CharField",
        "PositiveBigIntegerField",
        "DateTimeField",
        "DateTimeField",
        "DateTimeField",
        "DateTimeField",
        "ForeignKey",
    ),
    "SecurityOperation": (
        "UUIDField",
        "CharField",
        "CharField",
        "PositiveBigIntegerField",
        "PositiveBigIntegerField",
        "PositiveBigIntegerField",
        "UUIDField",
        "UUIDField",
        "PositiveBigIntegerField",
        "DateTimeField",
        "DateTimeField",
        "DateTimeField",
        "ForeignKey",
        "ForeignKey",
    ),
}

_EXPECTED_OPERATION_PROFILE = (
    ("CreateModel", "Report"),
    ("CreateModel", "ReportLease"),
    ("CreateModel", "SecurityOperation"),
    ("AddIndex", "reportlease"),
    *(("AddConstraint", "reportlease"),) * 8,
    ("AddIndex", "securityoperation"),
    *(("AddConstraint", "securityoperation"),) * 8,
)
_ALLOWED_OPERATION_TYPES = frozenset(
    {"AddConstraint", "AddIndex", "CreateModel"}
)
_ALLOWED_CALLS = frozenset(
    {
        "migrations.AddConstraint",
        "migrations.AddIndex",
        "migrations.CreateModel",
        "models.CharField",
        "models.CheckConstraint",
        "models.DateTimeField",
        "models.F",
        "models.ForeignKey",
        "models.Index",
        "models.PositiveBigIntegerField",
        "models.Q",
        "models.UUIDField",
        "models.UniqueConstraint",
    }
)
_DYNAMIC_EXPRESSION_TYPES = (
    ast.Await,
    ast.DictComp,
    ast.GeneratorExp,
    ast.IfExp,
    ast.Lambda,
    ast.ListComp,
    ast.NamedExpr,
    ast.SetComp,
    ast.Yield,
    ast.YieldFrom,
)


def _violation(
    *,
    code: MigrationViolationCode,
    relative_path: str,
    line: int,
    detail_code: str,
) -> MigrationViolation:
    return MigrationViolation(
        code=code,
        relative_path=relative_path,
        line=line,
        detail_code=detail_code,
    )


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    values = [item.value for item in call.keywords if item.arg == name]
    return values[0] if len(values) == 1 else None


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    return None


def _class_assignment(
    migration_class: ast.ClassDef, name: str
) -> ast.Assign | None:
    matches = [
        node
        for node in migration_class.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    return matches[0] if len(matches) == 1 else None


def _operation_identity(call: ast.Call) -> tuple[str, str] | None:
    if not (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "migrations"
    ):
        return None
    operation_type = call.func.attr
    if operation_type == "CreateModel":
        model_name = _literal_string(_keyword(call, "name"))
    else:
        model_name = _literal_string(_keyword(call, "model_name"))
    if model_name is None:
        return None
    return operation_type, model_name


def _created_model_fields(
    call: ast.Call,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    fields_node = _keyword(call, "fields")
    if not isinstance(fields_node, (ast.List, ast.Tuple)):
        return None
    field_names: list[str] = []
    field_types: list[str] = []
    for field_node in fields_node.elts:
        if not (
            isinstance(field_node, (ast.List, ast.Tuple))
            and len(field_node.elts) == 2
        ):
            return None
        field_name = _literal_string(field_node.elts[0])
        field_value = field_node.elts[1]
        if not (
            isinstance(field_value, ast.Call)
            and isinstance(field_value.func, ast.Attribute)
            and isinstance(field_value.func.value, ast.Name)
            and field_value.func.value.id == "models"
            and field_name is not None
        ):
            return None
        field_names.append(field_name)
        field_types.append(field_value.func.attr)
    return tuple(field_names), tuple(field_types)


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return f"{call.func.value.id}.{call.func.attr}"
    return None


def _module_profile_is_exact(tree: ast.Module) -> bool:
    if len(tree.body) != 4:
        return False
    first, second, third, fourth = tree.body
    return (
        isinstance(first, ast.Import)
        and len(first.names) == 1
        and first.names[0].name == "django.db.models.deletion"
        and first.names[0].asname is None
        and isinstance(second, ast.Import)
        and len(second.names) == 1
        and second.names[0].name == "uuid"
        and second.names[0].asname is None
        and isinstance(third, ast.ImportFrom)
        and third.level == 0
        and third.module == "django.db"
        and [(alias.name, alias.asname) for alias in third.names]
        == [("migrations", None), ("models", None)]
        and isinstance(fourth, ast.ClassDef)
        and fourth.name == "Migration"
    )


def analyze_lifecycle_migration_source(
    *, source: str, relative_path: str
) -> tuple[MigrationViolation, ...]:
    """Validate the exact inert migration shape without importing it."""

    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=MigrationViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )

    if not _module_profile_is_exact(tree):
        return (
            _violation(
                code=MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                relative_path=relative_path,
                line=0,
                detail_code="MODULE_PROFILE",
            ),
        )

    migration_classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Migration"
    ]
    if len(migration_classes) != 1:
        return (
            _violation(
                code=MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                relative_path=relative_path,
                line=0,
                detail_code="MIGRATION_CLASS",
            ),
        )
    migration_class = migration_classes[0]
    if not (
        len(migration_class.bases) == 1
        and isinstance(migration_class.bases[0], ast.Attribute)
        and isinstance(migration_class.bases[0].value, ast.Name)
        and migration_class.bases[0].value.id == "migrations"
        and migration_class.bases[0].attr == "Migration"
        and not migration_class.keywords
        and not migration_class.decorator_list
        and len(migration_class.body) == 3
    ):
        return (
            _violation(
                code=MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                relative_path=relative_path,
                line=migration_class.lineno,
                detail_code="MIGRATION_CLASS_PROFILE",
            ),
        )
    initial = _class_assignment(migration_class, "initial")
    dependencies = _class_assignment(migration_class, "dependencies")
    operations = _class_assignment(migration_class, "operations")
    graph_valid = (
        initial is not None
        and isinstance(initial.value, ast.Constant)
        and initial.value.value is True
        and dependencies is not None
        and isinstance(dependencies.value, (ast.List, ast.Tuple))
        and not dependencies.value.elts
        and operations is not None
        and isinstance(operations.value, (ast.List, ast.Tuple))
    )
    if not graph_valid:
        return (
            _violation(
                code=MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                relative_path=relative_path,
                line=migration_class.lineno,
                detail_code="INITIAL_GRAPH_PROFILE",
            ),
        )

    violations: list[MigrationViolation] = []
    for node in ast.walk(operations.value):
        if isinstance(node, ast.Call) and _call_name(node) not in _ALLOWED_CALLS:
            violations.append(
                _violation(
                    code=MigrationViolationCode.OPERATION_DISALLOWED,
                    relative_path=relative_path,
                    line=node.lineno,
                    detail_code="CALL_NOT_ALLOWLISTED",
                )
            )
        elif isinstance(node, _DYNAMIC_EXPRESSION_TYPES):
            violations.append(
                _violation(
                    code=MigrationViolationCode.OPERATION_DISALLOWED,
                    relative_path=relative_path,
                    line=node.lineno,
                    detail_code="DYNAMIC_EXPRESSION",
                )
            )
    operation_profile: list[tuple[str, str]] = []
    created_models: dict[str, tuple[str, ...]] = {}
    created_field_types: dict[str, tuple[str, ...]] = {}
    for operation_node in operations.value.elts:
        if not isinstance(operation_node, ast.Call):
            violations.append(
                _violation(
                    code=MigrationViolationCode.OPERATION_DISALLOWED,
                    relative_path=relative_path,
                    line=getattr(operation_node, "lineno", 0),
                    detail_code="DYNAMIC_OPERATION",
                )
            )
            continue
        identity = _operation_identity(operation_node)
        if identity is None or identity[0] not in _ALLOWED_OPERATION_TYPES:
            violations.append(
                _violation(
                    code=MigrationViolationCode.OPERATION_DISALLOWED,
                    relative_path=relative_path,
                    line=operation_node.lineno,
                    detail_code="OPERATION_NOT_ALLOWLISTED",
                )
            )
            continue
        operation_profile.append(identity)
        operation_type, model_name = identity
        if operation_type == "CreateModel":
            field_profile = _created_model_fields(operation_node)
            if field_profile is None:
                violations.append(
                    _violation(
                        code=MigrationViolationCode.FIELD_PROFILE_MISMATCH,
                        relative_path=relative_path,
                        line=operation_node.lineno,
                        detail_code="DYNAMIC_FIELD_PROFILE",
                    )
                )
            else:
                field_names, field_types = field_profile
                created_models[model_name] = field_names
                created_field_types[model_name] = field_types

    if tuple(operation_profile) != _EXPECTED_OPERATION_PROFILE:
        violations.append(
            _violation(
                code=MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                relative_path=relative_path,
                line=operations.lineno,
                detail_code="OPERATION_PROFILE",
            )
        )
    if set(created_models) != set(EXPECTED_LIFECYCLE_MIGRATION_FIELDS):
        violations.append(
            _violation(
                code=MigrationViolationCode.MODEL_PROFILE_MISMATCH,
                relative_path=relative_path,
                line=operations.lineno,
                detail_code="MODEL_SET",
            )
        )
    for model_name, expected_fields in EXPECTED_LIFECYCLE_MIGRATION_FIELDS.items():
        if created_models.get(model_name) != expected_fields:
            violations.append(
                _violation(
                    code=MigrationViolationCode.FIELD_PROFILE_MISMATCH,
                    relative_path=relative_path,
                    line=operations.lineno,
                    detail_code=model_name,
                )
            )
        if created_field_types.get(model_name) != _EXPECTED_FIELD_TYPE_PROFILE[
            model_name
        ]:
            violations.append(
                _violation(
                    code=MigrationViolationCode.FIELD_PROFILE_MISMATCH,
                    relative_path=relative_path,
                    line=operations.lineno,
                    detail_code=f"{model_name}_TYPE_PROFILE",
                )
            )
    return tuple(
        sorted(
            violations,
            key=lambda item: (
                item.relative_path,
                item.line,
                item.code.value,
                item.detail_code,
            ),
        )
    )


def scan_lifecycle_migrations(
    *, migrations_root: Path, relative_to: Path
) -> tuple[MigrationViolation, ...]:
    """Require one exact initial migration and no additional migration graph."""

    try:
        resolved_root = relative_to.resolve(strict=True)
        resolved_migrations = migrations_root.resolve(strict=True)
        resolved_migrations.relative_to(resolved_root)
        relative_root = migrations_root.relative_to(relative_to).as_posix()
    except (OSError, ValueError):
        return (
            _violation(
                code=MigrationViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-migration-path>",
                line=0,
                detail_code="PATH_INVALID",
            ),
        )
    numbered_files = tuple(
        sorted(
            path
            for path in resolved_migrations.glob("[0-9][0-9][0-9][0-9]_*.py")
            if path.is_file()
        )
    )
    if tuple(path.name for path in numbered_files) != ("0001_initial.py",):
        return (
            _violation(
                code=MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                relative_path=relative_root,
                line=0,
                detail_code="NUMBERED_FILE_SET",
            ),
        )
    migration_path = numbered_files[0]
    try:
        source = migration_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (
            _violation(
                code=MigrationViolationCode.SOURCE_PARSE_ERROR,
                relative_path=f"{relative_root}/0001_initial.py",
                line=0,
                detail_code="SOURCE_UNREADABLE",
            ),
        )
    return analyze_lifecycle_migration_source(
        source=source,
        relative_path=f"{relative_root}/0001_initial.py",
    )
