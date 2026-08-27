"""Non-executing purity policy for the inert lifecycle orchestrators."""

import ast
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class OrchestrationViolationCode(StrEnum):
    CALL_DISALLOWED = "CALL_DISALLOWED"
    DYNAMIC_CONSTRUCT = "DYNAMIC_CONSTRUCT"
    EXECUTOR_PROFILE_MISMATCH = "EXECUTOR_PROFILE_MISMATCH"
    IMPORT_PROFILE_MISMATCH = "IMPORT_PROFILE_MISMATCH"
    MODULE_PROFILE_MISMATCH = "MODULE_PROFILE_MISMATCH"
    PLAN_PROFILE_MISMATCH = "PLAN_PROFILE_MISMATCH"
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class OrchestrationSourceViolation:
    code: OrchestrationViolationCode
    relative_path: str
    line: int
    detail_code: str


ImportIdentity = tuple[int, str | None, tuple[tuple[str, str | None], ...]]


@dataclass(frozen=True, slots=True)
class OrchestrationSourcePolicy:
    name: str
    relative_path: str
    expected_imports: tuple[ImportIdentity, ...]
    expected_module_members: tuple[tuple[str, str], ...]
    allowed_calls: frozenset[str]
    allowed_raises: frozenset[str]
    plan_class_name: str
    plan_fields: tuple[tuple[str, str], ...]
    plan_false_classvars: tuple[str, ...]
    executor_name: str
    unavailable_error_name: str


_COMMON_IMPORTS: tuple[ImportIdentity, ...] = (
    (0, "dataclasses", (("dataclass", None),)),
    (0, "datetime", (("datetime", None),)),
    (0, "enum", (("StrEnum", None),)),
    (0, "types", (("MappingProxyType", None),)),
    (0, "typing", (("ClassVar", None), ("Never", None))),
    (0, "uuid", (("UUID", None),)),
    (0, "django.utils", (("timezone", None),)),
    (
        1,
        "bindings",
        (
            ("SecurityOperationCommand", None),
            ("ValidatedSecurityOperationBinding", None),
        ),
    ),
)

_COMMON_PLAN_FIELDS = (
    ("operation_id", "UUID"),
    ("idempotency_id", "UUID"),
    ("report_id", "UUID"),
    ("operator_id", "UUID"),
    ("lease_id", "UUID"),
    ("report_state_version", "int"),
    ("lease_generation", "int"),
)

FINALIZATION_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="FINALIZATION_INERT_SOURCE_V1",
    relative_path="report_lifecycle/finalization.py",
    expected_imports=(
        *_COMMON_IMPORTS,
        (1, "errors", (("FinalizationOrchestrationUnavailable", None), ("LifecycleTransitionDenied", None))),
        (1, "states", (("ReportState", None), ("SecurityOperationKind", None))),
        (1, "transitions", (("LeaseActivityPlan", None), ("MAX_STATE_VERSION", None))),
    ),
    expected_module_members=(
        ("class", "FinalizationCheckpoint"),
        ("assign", "FINALIZATION_SEQUENCE"),
        ("assign", "FINALIZATION_TRANSITIONS"),
        ("class", "InertFinalizationStepPlan"),
        ("function", "_valid_counter"),
        ("function", "_require_finalization_binding"),
        ("function", "plan_inert_finalization_step"),
        ("function", "execute_finalization_step"),
    ),
    allowed_calls=frozenset({
        "FinalizationOrchestrationUnavailable", "InertFinalizationStepPlan",
        "LifecycleTransitionDenied", "MappingProxyType", "_valid_counter",
        "_require_finalization_binding", "dataclass", "enumerate", "frozenset",
        "len", "set", "timezone.is_aware", "type",
    }),
    allowed_raises=frozenset({"FinalizationOrchestrationUnavailable", "LifecycleTransitionDenied"}),
    plan_class_name="InertFinalizationStepPlan",
    plan_fields=(*_COMMON_PLAN_FIELDS, ("source_checkpoint", "FinalizationCheckpoint"), ("target_checkpoint", "FinalizationCheckpoint")),
    plan_false_classvars=("authorizes_execution", "persists_checkpoint"),
    executor_name="execute_finalization_step",
    unavailable_error_name="FinalizationOrchestrationUnavailable",
)

DELETION_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="OPERATOR_DELETION_INERT_SOURCE_V1",
    relative_path="report_lifecycle/deletion.py",
    expected_imports=(
        *_COMMON_IMPORTS,
        (1, "errors", (("DeletionOrchestrationUnavailable", None), ("LifecycleTransitionDenied", None))),
        (1, "states", (("ReportState", None), ("SecurityOperationKind", None))),
        (1, "transitions", (("LeaseActivityPlan", None), ("MAX_STATE_VERSION", None))),
    ),
    expected_module_members=(
        ("class", "OperatorDeletionCheckpoint"),
        ("assign", "OPERATOR_DELETION_SEQUENCE"),
        ("assign", "OPERATOR_DELETION_TRANSITIONS"),
        ("class", "InertOperatorDeletionStepPlan"),
        ("function", "_valid_counter"),
        ("function", "_require_operator_deletion_binding"),
        ("function", "plan_inert_operator_deletion_step"),
        ("function", "execute_operator_deletion_step"),
    ),
    allowed_calls=frozenset({
        "DeletionOrchestrationUnavailable", "InertOperatorDeletionStepPlan",
        "LifecycleTransitionDenied", "MappingProxyType", "_valid_counter",
        "_require_operator_deletion_binding", "dataclass", "enumerate",
        "frozenset", "len", "set", "timezone.is_aware", "tuple", "type",
    }),
    allowed_raises=frozenset({"DeletionOrchestrationUnavailable", "LifecycleTransitionDenied"}),
    plan_class_name="InertOperatorDeletionStepPlan",
    plan_fields=(*_COMMON_PLAN_FIELDS, ("source_checkpoint", "OperatorDeletionCheckpoint"), ("target_checkpoint", "OperatorDeletionCheckpoint")),
    plan_false_classvars=("authorizes_execution", "persists_checkpoint", "destroys_key_or_content"),
    executor_name="execute_operator_deletion_step",
    unavailable_error_name="DeletionOrchestrationUnavailable",
)

ORCHESTRATION_SOURCE_POLICIES = MappingProxyType({
    "deletion": DELETION_SOURCE_POLICY,
    "finalization": FINALIZATION_SOURCE_POLICY,
})

_DYNAMIC_NODE_TYPES = (
    ast.Assert, ast.AsyncFor, ast.AsyncFunctionDef, ast.AsyncWith, ast.AugAssign,
    ast.Await, ast.Delete, ast.For, ast.Global, ast.Lambda, ast.NamedExpr,
    ast.Nonlocal, ast.Try, ast.TryStar, ast.While, ast.With, ast.Yield,
    ast.YieldFrom,
)


def _violation(*, code: OrchestrationViolationCode, relative_path: str, line: int, detail_code: str) -> OrchestrationSourceViolation:
    return OrchestrationSourceViolation(code=code, relative_path=relative_path, line=line, detail_code=detail_code)


def _import_identity(node: ast.ImportFrom) -> ImportIdentity:
    return node.level, node.module, tuple((alias.name, alias.asname) for alias in node.names)


def _call_name(call: ast.Call) -> str | None:
    parts: list[str] = []
    current: ast.AST = call.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _module_member_identity(node: ast.stmt) -> tuple[str, str] | None:
    if isinstance(node, ast.ClassDef):
        return "class", node.name
    if isinstance(node, ast.FunctionDef):
        return "function", node.name
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return "assign", node.targets[0].id
    return None


def _module_members(tree: ast.Module) -> tuple[tuple[str, str], ...] | None:
    members: list[tuple[str, str]] = []
    for index, node in enumerate(tree.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            continue
        if isinstance(node, ast.ImportFrom):
            continue
        identity = _module_member_identity(node)
        if identity is None:
            return None
        members.append(identity)
    return tuple(members)


def _annotation_text(node: ast.AST | None) -> str:
    return ast.unparse(node) if node is not None else ""


def _literal_bool(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and type(node.value) is bool:
        return node.value
    return None


def _dataclass_profile_is_exact(node: ast.ClassDef) -> bool:
    if len(node.decorator_list) != 1:
        return False
    decorator = node.decorator_list[0]
    return (
        isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
        and decorator.func.id == "dataclass" and not decorator.args
        and [(item.arg, _literal_bool(item.value)) for item in decorator.keywords]
        == [("frozen", True), ("slots", True)]
        and not node.bases and not node.keywords
    )


def _plan_profile_is_exact(tree: ast.Module, policy: OrchestrationSourcePolicy) -> bool:
    matches = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == policy.plan_class_name]
    if len(matches) != 1 or not _dataclass_profile_is_exact(matches[0]):
        return False
    annotations = matches[0].body
    if not all(isinstance(node, ast.AnnAssign) and node.simple == 1 and isinstance(node.target, ast.Name) for node in annotations):
        return False
    fields: list[tuple[str, str]] = []
    false_classvars: list[str] = []
    for annotation in annotations:
        if not (
            isinstance(annotation, ast.AnnAssign)
            and isinstance(annotation.target, ast.Name)
        ):
            return False
        name = annotation.target.id
        annotation_text = _annotation_text(annotation.annotation)
        if annotation.value is None:
            fields.append((name, annotation_text))
        elif annotation_text == "ClassVar[bool]" and isinstance(annotation.value, ast.Constant) and annotation.value.value is False:
            false_classvars.append(name)
        else:
            return False
    return tuple(fields) == policy.plan_fields and tuple(false_classvars) == policy.plan_false_classvars


def _is_unavailable_raise(node: ast.stmt, policy: OrchestrationSourcePolicy) -> bool:
    return (
        isinstance(node, ast.Raise) and node.cause is None and isinstance(node.exc, ast.Call)
        and _call_name(node.exc) == policy.unavailable_error_name
        and not node.exc.args and not node.exc.keywords
    )


def _executor_profile_is_exact(tree: ast.Module, policy: OrchestrationSourcePolicy) -> bool:
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == policy.executor_name]
    if len(matches) != 1:
        return False
    function = matches[0]
    arguments = function.args
    if not (
        not function.decorator_list and not arguments.posonlyargs and not arguments.args
        and arguments.vararg is None and arguments.kwarg is None
        and len(arguments.kwonlyargs) == 1 and arguments.kwonlyargs[0].arg == "plan"
        and _annotation_text(arguments.kwonlyargs[0].annotation) == policy.plan_class_name
        and arguments.kw_defaults == [None] and function.returns is not None
        and _annotation_text(function.returns) == "Never" and len(function.body) == 3
        and isinstance(function.body[0], ast.Expr) and isinstance(function.body[0].value, ast.Constant)
        and type(function.body[0].value.value) is str
    ):
        return False
    guard = function.body[1]
    if not (
        isinstance(guard, ast.If) and not guard.orelse and len(guard.body) == 1
        and _is_unavailable_raise(guard.body[0], policy)
        and isinstance(guard.test, ast.Compare) and len(guard.test.ops) == 1
        and isinstance(guard.test.ops[0], ast.IsNot) and len(guard.test.comparators) == 1
        and isinstance(guard.test.left, ast.Call) and _call_name(guard.test.left) == "type"
        and len(guard.test.left.args) == 1 and isinstance(guard.test.left.args[0], ast.Name)
        and guard.test.left.args[0].id == "plan" and not guard.test.left.keywords
        and isinstance(guard.test.comparators[0], ast.Name)
        and guard.test.comparators[0].id == policy.plan_class_name
    ):
        return False
    return _is_unavailable_raise(function.body[2], policy)


def _raise_is_allowlisted(node: ast.Raise, policy: OrchestrationSourcePolicy) -> bool:
    return (
        node.cause is None and isinstance(node.exc, ast.Call)
        and _call_name(node.exc) in policy.allowed_raises
        and not node.exc.args and not node.exc.keywords
    )


def analyze_inert_orchestration_source(*, source: str, relative_path: str, policy: OrchestrationSourcePolicy) -> tuple[OrchestrationSourceViolation, ...]:
    """Validate source shape and purity without importing or executing it."""
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (_violation(code=OrchestrationViolationCode.SOURCE_PARSE_ERROR, relative_path=relative_path, line=0, detail_code="PYTHON_SOURCE_INVALID"),)

    violations: list[OrchestrationSourceViolation] = []
    imports = tuple(_import_identity(node) for node in tree.body if isinstance(node, ast.ImportFrom))
    all_import_nodes = tuple(
        node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
    )
    if (
        any(isinstance(node, ast.Import) for node in all_import_nodes)
        or len(all_import_nodes) != len(imports)
        or imports != policy.expected_imports
    ):
        violations.append(_violation(code=OrchestrationViolationCode.IMPORT_PROFILE_MISMATCH, relative_path=relative_path, line=0, detail_code="IMPORT_SET_OR_ORDER"))
    if _module_members(tree) != policy.expected_module_members:
        violations.append(_violation(code=OrchestrationViolationCode.MODULE_PROFILE_MISMATCH, relative_path=relative_path, line=0, detail_code="TOP_LEVEL_MEMBER_PROFILE"))
    if not _plan_profile_is_exact(tree, policy):
        violations.append(_violation(code=OrchestrationViolationCode.PLAN_PROFILE_MISMATCH, relative_path=relative_path, line=0, detail_code="PLAN_DATACLASS_PROFILE"))
    if not _executor_profile_is_exact(tree, policy):
        violations.append(_violation(code=OrchestrationViolationCode.EXECUTOR_PROFILE_MISMATCH, relative_path=relative_path, line=0, detail_code="FAIL_CLOSED_EXECUTOR_PROFILE"))

    protected_call_roots = frozenset(
        call_name.partition(".")[0] for call_name in policy.allowed_calls
    )
    top_level_definitions = frozenset(
        id(node)
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
    )
    for node in ast.walk(tree):
        if isinstance(node, _DYNAMIC_NODE_TYPES):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=getattr(node, "lineno", 0), detail_code="DYNAMIC_OR_EFFECTFUL_SYNTAX"))
        elif (
            isinstance(node, (ast.ClassDef, ast.FunctionDef))
            and id(node) not in top_level_definitions
        ):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="NESTED_DEFINITION"))
        elif isinstance(node, ast.arg) and node.arg in protected_call_roots:
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="CALL_NAME_REBOUND"))
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id in protected_call_roots
        ):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="CALL_NAME_REBOUND"))
        elif isinstance(node, ast.Call) and _call_name(node) not in policy.allowed_calls:
            violations.append(_violation(code=OrchestrationViolationCode.CALL_DISALLOWED, relative_path=relative_path, line=node.lineno, detail_code="CALL_NOT_ALLOWLISTED"))
        elif isinstance(node, ast.Raise) and not _raise_is_allowlisted(node, policy):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="RAISE_NOT_ALLOWLISTED"))
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, ast.Store):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="MUTATING_TARGET"))
    return tuple(sorted(set(violations), key=lambda item: (item.relative_path, item.line, item.code.value, item.detail_code)))


def scan_inert_orchestration_sources(*, lifecycle_root: Path, relative_to: Path) -> tuple[OrchestrationSourceViolation, ...]:
    """Scan only the two approved inert orchestration source targets."""
    try:
        resolved_root = relative_to.resolve(strict=True)
        resolved_lifecycle = lifecycle_root.resolve(strict=True)
        resolved_lifecycle.relative_to(resolved_root)
        lifecycle_relative = lifecycle_root.relative_to(relative_to).as_posix()
    except (OSError, ValueError):
        return (_violation(code=OrchestrationViolationCode.SOURCE_PARSE_ERROR, relative_path="<invalid-orchestration-path>", line=0, detail_code="PATH_INVALID"),)
    if lifecycle_relative != "report_lifecycle":
        return (_violation(code=OrchestrationViolationCode.SOURCE_PARSE_ERROR, relative_path="<invalid-orchestration-path>", line=0, detail_code="PATH_INVALID"),)

    expected_names = frozenset(Path(policy.relative_path).name for policy in ORCHESTRATION_SOURCE_POLICIES.values())
    try:
        present_names = frozenset(
            path.name
            for path in resolved_lifecycle.iterdir()
            if path.is_file() and path.name in expected_names
        )
    except OSError:
        return (_violation(code=OrchestrationViolationCode.SOURCE_PARSE_ERROR, relative_path=lifecycle_relative, line=0, detail_code="SOURCE_UNREADABLE"),)
    if present_names != expected_names:
        return (_violation(code=OrchestrationViolationCode.TARGET_SET_MISMATCH, relative_path=lifecycle_relative, line=0, detail_code="TARGET_FILE_SET"),)

    violations: list[OrchestrationSourceViolation] = []
    for policy in ORCHESTRATION_SOURCE_POLICIES.values():
        path = relative_to / policy.relative_path
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
            source = resolved_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            violations.append(_violation(code=OrchestrationViolationCode.SOURCE_PARSE_ERROR, relative_path=policy.relative_path, line=0, detail_code="SOURCE_UNREADABLE"))
            continue
        violations.extend(analyze_inert_orchestration_source(source=source, relative_path=policy.relative_path, policy=policy))
    return tuple(violations)
