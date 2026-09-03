"""Non-executing purity policy for the inert lifecycle orchestrators."""

import ast
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class OrchestrationViolationCode(StrEnum):
    CALL_DISALLOWED = "CALL_DISALLOWED"
    DYNAMIC_CONSTRUCT = "DYNAMIC_CONSTRUCT"
    ENUM_PROFILE_MISMATCH = "ENUM_PROFILE_MISMATCH"
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
DataclassIdentity = tuple[
    str,
    tuple[tuple[str, str], ...],
    tuple[str, ...],
]
StrEnumIdentity = tuple[str, tuple[tuple[str, str], ...]]


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
    additional_dataclasses: tuple[DataclassIdentity, ...] = ()
    expected_str_enums: tuple[StrEnumIdentity, ...] = ()


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

AUDIT_RETENTION_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="AUDIT_RETENTION_INERT_SOURCE_V1",
    relative_path="report_lifecycle/audit_retention.py",
    expected_imports=(
        (0, "dataclasses", (("dataclass", None),)),
        (
            0,
            "datetime",
            (("UTC", None), ("datetime", None), ("timedelta", None)),
        ),
        (0, "enum", (("StrEnum", None),)),
        (0, "typing", (("ClassVar", None), ("Never", None))),
        (0, "uuid", (("UUID", None),)),
        (0, "django.utils", (("timezone", None),)),
        (
            1,
            "errors",
            (
                ("AuditRetentionOrchestrationUnavailable", None),
                ("LifecycleTransitionDenied", None),
            ),
        ),
    ),
    expected_module_members=(
        ("assign", "EVENT_RETENTION_LIMIT"),
        ("assign", "VERIFICATION_RETENTION_LIMIT"),
        ("class", "AuditRetentionClass"),
        ("class", "AuditRetentionDisposition"),
        ("class", "AuditRetentionSnapshot"),
        ("class", "InertAuditRetentionPlan"),
        ("function", "_require_timestamp"),
        ("function", "_retention_limit"),
        ("function", "plan_inert_audit_retention"),
        ("function", "execute_audit_retention"),
    ),
    allowed_calls=frozenset(
        {
            "AuditRetentionOrchestrationUnavailable",
            "InertAuditRetentionPlan",
            "LifecycleTransitionDenied",
            "_require_timestamp",
            "_retention_limit",
            "dataclass",
            "timedelta",
            "timezone.is_aware",
            "timezone.localtime",
            "timezone.now",
            "type",
        }
    ),
    allowed_raises=frozenset(
        {
            "AuditRetentionOrchestrationUnavailable",
            "LifecycleTransitionDenied",
        }
    ),
    plan_class_name="InertAuditRetentionPlan",
    plan_fields=(
        ("retention_id", "UUID"),
        ("evidence_id", "UUID"),
        ("evidence_class", "AuditRetentionClass"),
        ("collector_recorded_at", "datetime"),
        ("observed_at", "datetime"),
        ("earliest_expiry_review_at", "datetime"),
        ("verification_dependency_required", "bool"),
        ("disposition", "AuditRetentionDisposition"),
    ),
    plan_false_classvars=(
        "authorizes_expiry",
        "deletes_audit_evidence",
        "persists_retention_batch",
        "exposes_witness_evidence",
        "calls_external_service",
    ),
    executor_name="execute_audit_retention",
    unavailable_error_name="AuditRetentionOrchestrationUnavailable",
    additional_dataclasses=(
        (
            "AuditRetentionSnapshot",
            (
                ("retention_id", "UUID"),
                ("evidence_id", "UUID"),
                ("evidence_class", "AuditRetentionClass"),
                ("collector_recorded_at", "datetime"),
                ("verification_dependency_required", "bool"),
            ),
            (),
        ),
    ),
    expected_str_enums=(
        (
            "AuditRetentionClass",
            (
                ("EVENT_RECEIPT_OR_PROOF", "EVENT_RECEIPT_OR_PROOF"),
                (
                    "CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS",
                    "CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS",
                ),
            ),
        ),
        (
            "AuditRetentionDisposition",
            (
                ("RETAIN_MINIMUM_PERIOD", "RETAIN_MINIMUM_PERIOD"),
                (
                    "RETAIN_VERIFICATION_DEPENDENCY",
                    "RETAIN_VERIFICATION_DEPENDENCY",
                ),
                ("EXPIRY_REVIEW_DUE", "EXPIRY_REVIEW_DUE"),
            ),
        ),
    ),
)

CLEANUP_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="CIPHERTEXT_CLEANUP_INERT_SOURCE_V1",
    relative_path="report_lifecycle/cleanup.py",
    expected_imports=(
        (0, "dataclasses", (("dataclass", None),)),
        (
            0,
            "datetime",
            (("UTC", None), ("datetime", None), ("timedelta", None)),
        ),
        (0, "enum", (("StrEnum", None),)),
        (0, "typing", (("ClassVar", None), ("Never", None))),
        (0, "uuid", (("UUID", None),)),
        (0, "django.utils", (("timezone", None),)),
        (
            1,
            "errors",
            (
                ("CleanupOrchestrationUnavailable", None),
                ("LifecycleTransitionDenied", None),
            ),
        ),
        (1, "transitions", (("MAX_STATE_VERSION", None),)),
    ),
    expected_module_members=(
        ("assign", "FIRST_RETRY_DELAY"),
        ("assign", "SECOND_RETRY_DELAY"),
        ("assign", "THIRD_RETRY_DELAY"),
        ("assign", "FIRST_HOUR_RETRY_DELAY"),
        ("assign", "FIRST_DAY_RETRY_DELAY"),
        ("assign", "LONG_TERM_RETRY_DELAY"),
        ("assign", "FIRST_HOUR_BOUNDARY"),
        ("assign", "FIRST_DAY_BOUNDARY"),
        ("assign", "PERSISTENT_FAILURE_ALERT_DELAY"),
        ("assign", "MAXIMUM_RECONCILER_INTERVAL"),
        ("assign", "MAXIMUM_JITTER_FRACTION"),
        ("class", "CleanupRetryTier"),
        ("class", "CleanupAlertDisposition"),
        ("class", "CleanupFailureSnapshot"),
        ("class", "InertCleanupRetryPlan"),
        ("function", "_require_timestamp"),
        ("function", "_retry_profile"),
        ("function", "plan_inert_cleanup_retry"),
        ("function", "execute_cleanup_retry"),
    ),
    allowed_calls=frozenset(
        {
            "CleanupOrchestrationUnavailable",
            "InertCleanupRetryPlan",
            "LifecycleTransitionDenied",
            "_require_timestamp",
            "_retry_profile",
            "dataclass",
            "timedelta",
            "timezone.is_aware",
            "timezone.localtime",
            "timezone.now",
            "type",
        }
    ),
    allowed_raises=frozenset(
        {
            "CleanupOrchestrationUnavailable",
            "LifecycleTransitionDenied",
        }
    ),
    plan_class_name="InertCleanupRetryPlan",
    plan_fields=(
        ("cleanup_id", "UUID"),
        ("idempotency_id", "UUID"),
        ("failure_count", "int"),
        ("first_failed_at", "datetime"),
        ("last_failed_at", "datetime"),
        ("observed_at", "datetime"),
        ("retry_tier", "CleanupRetryTier"),
        ("base_retry_delay", "timedelta"),
        ("maximum_jitter", "timedelta"),
        ("next_base_retry_at", "datetime"),
        ("persistent_alert_due_at", "datetime"),
        ("alert_disposition", "CleanupAlertDisposition"),
    ),
    plan_false_classvars=(
        "authorizes_deletion",
        "schedules_task",
        "persists_state",
        "submits_alert",
        "calls_external_service",
    ),
    executor_name="execute_cleanup_retry",
    unavailable_error_name="CleanupOrchestrationUnavailable",
    additional_dataclasses=(
        (
            "CleanupFailureSnapshot",
            (
                ("cleanup_id", "UUID"),
                ("idempotency_id", "UUID"),
                ("failure_count", "int"),
                ("first_failed_at", "datetime"),
                ("last_failed_at", "datetime"),
                ("persistent_alert_recorded_at", "datetime | None"),
            ),
            (),
        ),
    ),
    expected_str_enums=(
        (
            "CleanupRetryTier",
            (
                ("FIRST_FIVE_SECONDS", "FIRST_FIVE_SECONDS"),
                ("SECOND_THIRTY_SECONDS", "SECOND_THIRTY_SECONDS"),
                ("THIRD_TWO_MINUTES", "THIRD_TWO_MINUTES"),
                ("FIVE_MINUTES_FIRST_HOUR", "FIVE_MINUTES_FIRST_HOUR"),
                ("HOURLY_THROUGH_FIRST_DAY", "HOURLY_THROUGH_FIRST_DAY"),
                ("SIX_HOURLY_INDEFINITE", "SIX_HOURLY_INDEFINITE"),
            ),
        ),
        (
            "CleanupAlertDisposition",
            (
                ("NOT_DUE", "NOT_DUE"),
                ("SUBMISSION_DUE", "SUBMISSION_DUE"),
                ("RECORDED", "RECORDED"),
            ),
        ),
    ),
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

EMERGENCY_EXPORT_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="EMERGENCY_EXPORT_INERT_SOURCE_V1",
    relative_path="report_lifecycle/emergency_export.py",
    expected_imports=(
        *_COMMON_IMPORTS,
        (
            1,
            "errors",
            (
                ("EmergencyExportOrchestrationUnavailable", None),
                ("LifecycleTransitionDenied", None),
            ),
        ),
        (1, "states", (("ReportState", None), ("SecurityOperationKind", None))),
        (
            1,
            "transitions",
            (("LeaseActivityPlan", None), ("MAX_STATE_VERSION", None)),
        ),
    ),
    expected_module_members=(
        ("class", "EmergencyExportCheckpoint"),
        ("assign", "EMERGENCY_EXPORT_SEQUENCE"),
        ("assign", "EMERGENCY_EXPORT_TRANSITIONS"),
        ("class", "InertEmergencyExportStepPlan"),
        ("function", "_valid_counter"),
        ("function", "_require_emergency_export_binding"),
        ("function", "plan_inert_emergency_export_step"),
        ("function", "execute_emergency_export_step"),
    ),
    allowed_calls=frozenset(
        {
            "EmergencyExportOrchestrationUnavailable",
            "InertEmergencyExportStepPlan",
            "LifecycleTransitionDenied",
            "MappingProxyType",
            "_require_emergency_export_binding",
            "_valid_counter",
            "dataclass",
            "enumerate",
            "frozenset",
            "len",
            "set",
            "timezone.is_aware",
            "tuple",
            "type",
        }
    ),
    allowed_raises=frozenset(
        {
            "EmergencyExportOrchestrationUnavailable",
            "LifecycleTransitionDenied",
        }
    ),
    plan_class_name="InertEmergencyExportStepPlan",
    plan_fields=(
        *_COMMON_PLAN_FIELDS,
        ("source_checkpoint", "EmergencyExportCheckpoint"),
        ("target_checkpoint", "EmergencyExportCheckpoint"),
    ),
    plan_false_classvars=(
        "authorizes_execution",
        "persists_checkpoint",
        "creates_export_artifact",
        "releases_plaintext",
    ),
    executor_name="execute_emergency_export_step",
    unavailable_error_name="EmergencyExportOrchestrationUnavailable",
    expected_str_enums=(
        (
            "EmergencyExportCheckpoint",
            (
                ("CONTEXT_VALIDATED", "CONTEXT_VALIDATED"),
                (
                    "REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED",
                    "REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED",
                ),
                (
                    "REQUESTED_AUDIT_RECEIPT_OBTAINED",
                    "REQUESTED_AUDIT_RECEIPT_OBTAINED",
                ),
                (
                    "ADMINISTRATOR_ALERT_ACCEPTED",
                    "ADMINISTRATOR_ALERT_ACCEPTED",
                ),
                (
                    "AUTHORIZED_JOB_AND_FENCE_COMMITTED",
                    "AUTHORIZED_JOB_AND_FENCE_COMMITTED",
                ),
                ("AUTHORIZED_AUDIT_ACCEPTED", "AUTHORIZED_AUDIT_ACCEPTED"),
                ("ENCRYPTED_STAGING_CREATED", "ENCRYPTED_STAGING_CREATED"),
                ("ENCRYPTED_STAGING_VERIFIED", "ENCRYPTED_STAGING_VERIFIED"),
                (
                    "COMPLETED_AUDIT_RECEIPT_OBTAINED",
                    "COMPLETED_AUDIT_RECEIPT_OBTAINED",
                ),
                (
                    "DELIVERY_CONTEXT_REVALIDATED",
                    "DELIVERY_CONTEXT_REVALIDATED",
                ),
                (
                    "DELIVERY_CONSUMED_AND_CLEANUP_STARTED",
                    "DELIVERY_CONSUMED_AND_CLEANUP_STARTED",
                ),
            ),
        ),
    ),
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

RETENTION_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="RESPONSE_RETENTION_INERT_SOURCE_V1",
    relative_path="report_lifecycle/retention.py",
    expected_imports=(
        (0, "dataclasses", (("dataclass", None),)),
        (
            0,
            "datetime",
            (("UTC", None), ("datetime", None), ("timedelta", None)),
        ),
        (0, "enum", (("StrEnum", None),)),
        (0, "typing", (("ClassVar", None), ("Never", None))),
        (0, "uuid", (("UUID", None),)),
        (0, "django.utils", (("timezone", None),)),
        (
            1,
            "errors",
            (
                ("LifecycleTransitionDenied", None),
                ("ResponseRetentionOrchestrationUnavailable", None),
            ),
        ),
        (1, "states", (("ReportState", None),)),
        (1, "transitions", (("MAX_STATE_VERSION", None),)),
    ),
    expected_module_members=(
        ("assign", "UNREAD_RESPONSE_LIMIT"),
        ("assign", "READ_RESPONSE_LIMIT"),
        ("class", "ResponseRetentionDisposition"),
        ("class", "ResponseRetentionSnapshot"),
        ("class", "InertResponseRetentionPlan"),
        ("function", "_require_timestamp"),
        ("function", "_elapsed_deadline"),
        ("function", "_require_snapshot"),
        ("function", "plan_inert_response_retention"),
        ("function", "execute_response_retention"),
    ),
    allowed_calls=frozenset(
        {
            "InertResponseRetentionPlan",
            "LifecycleTransitionDenied",
            "ResponseRetentionOrchestrationUnavailable",
            "_elapsed_deadline",
            "_require_snapshot",
            "_require_timestamp",
            "dataclass",
            "timedelta",
            "timezone.is_aware",
            "timezone.localtime",
            "timezone.now",
            "type",
        }
    ),
    allowed_raises=frozenset(
        {
            "LifecycleTransitionDenied",
            "ResponseRetentionOrchestrationUnavailable",
        }
    ),
    plan_class_name="InertResponseRetentionPlan",
    plan_fields=(
        ("report_id", "UUID"),
        ("response_id", "UUID"),
        ("report_state", "ReportState"),
        ("state_version", "int"),
        ("observed_at", "datetime"),
        ("unread_expires_at", "datetime"),
        ("first_read_at", "datetime | None"),
        ("response_expires_at", "datetime | None"),
        ("disposition", "ResponseRetentionDisposition"),
    ),
    plan_false_classvars=(
        "authorizes_recovery",
        "persists_deadline",
        "decrypts_response",
        "destroys_key_or_content",
    ),
    executor_name="execute_response_retention",
    unavailable_error_name="ResponseRetentionOrchestrationUnavailable",
    additional_dataclasses=(
        (
            "ResponseRetentionSnapshot",
            (
                ("report_id", "UUID"),
                ("response_id", "UUID"),
                ("report_state", "ReportState"),
                ("state_version", "int"),
                ("response_available_at", "datetime"),
                ("unread_expires_at", "datetime"),
                ("first_read_at", "datetime | None"),
                ("response_expires_at", "datetime | None"),
            ),
            (),
        ),
    ),
    expected_str_enums=(
        (
            "ResponseRetentionDisposition",
            (
                ("UNREAD_WINDOW_OPEN", "UNREAD_WINDOW_OPEN"),
                ("READ_WINDOW_OPEN", "READ_WINDOW_OPEN"),
                ("UNREAD_EXPIRY_DUE", "UNREAD_EXPIRY_DUE"),
                ("READ_EXPIRY_DUE", "READ_EXPIRY_DUE"),
            ),
        ),
    ),
)

METADATA_RETENTION_SOURCE_POLICY = OrchestrationSourcePolicy(
    name="TERMINAL_METADATA_RETENTION_INERT_SOURCE_V1",
    relative_path="report_lifecycle/metadata_retention.py",
    expected_imports=(
        (0, "dataclasses", (("dataclass", None),)),
        (
            0,
            "datetime",
            (("UTC", None), ("datetime", None), ("timedelta", None)),
        ),
        (0, "enum", (("StrEnum", None),)),
        (0, "typing", (("ClassVar", None), ("Never", None))),
        (0, "uuid", (("UUID", None),)),
        (0, "django.utils", (("timezone", None),)),
        (
            1,
            "errors",
            (
                ("LifecycleTransitionDenied", None),
                ("MetadataRetentionOrchestrationUnavailable", None),
            ),
        ),
    ),
    expected_module_members=(
        ("assign", "TERMINAL_METADATA_RETENTION_LIMIT"),
        ("class", "TerminalMetadataRetentionDisposition"),
        ("class", "TerminalMetadataRetentionSnapshot"),
        ("class", "InertTerminalMetadataRetentionPlan"),
        ("function", "_require_timestamp"),
        ("function", "plan_inert_terminal_metadata_retention"),
        ("function", "execute_terminal_metadata_retention"),
    ),
    allowed_calls=frozenset(
        {
            "InertTerminalMetadataRetentionPlan",
            "LifecycleTransitionDenied",
            "MetadataRetentionOrchestrationUnavailable",
            "_require_timestamp",
            "dataclass",
            "timedelta",
            "timezone.is_aware",
            "timezone.localtime",
            "timezone.now",
            "type",
        }
    ),
    allowed_raises=frozenset(
        {
            "LifecycleTransitionDenied",
            "MetadataRetentionOrchestrationUnavailable",
        }
    ),
    plan_class_name="InertTerminalMetadataRetentionPlan",
    plan_fields=(
        ("retention_id", "UUID"),
        ("cleanup_id", "UUID"),
        ("observed_at", "datetime"),
        ("cleanup_confirmed_at", "datetime | None"),
        ("earliest_removal_at", "datetime | None"),
        ("disposition", "TerminalMetadataRetentionDisposition"),
    ),
    plan_false_classvars=(
        "authorizes_removal",
        "deletes_ticket_lookup",
        "persists_state",
        "schedules_job",
        "calls_external_service",
    ),
    executor_name="execute_terminal_metadata_retention",
    unavailable_error_name="MetadataRetentionOrchestrationUnavailable",
    additional_dataclasses=(
        (
            "TerminalMetadataRetentionSnapshot",
            (
                ("retention_id", "UUID"),
                ("cleanup_id", "UUID"),
                ("cleanup_confirmed_at", "datetime | None"),
            ),
            (),
        ),
    ),
    expected_str_enums=(
        (
            "TerminalMetadataRetentionDisposition",
            (
                (
                    "RETAIN_CLEANUP_INCOMPLETE",
                    "RETAIN_CLEANUP_INCOMPLETE",
                ),
                ("RETAIN_MINIMUM_PERIOD", "RETAIN_MINIMUM_PERIOD"),
                ("REMOVAL_REVIEW_DUE", "REMOVAL_REVIEW_DUE"),
            ),
        ),
    ),
)

ORCHESTRATION_SOURCE_POLICIES = MappingProxyType({
    "audit_retention": AUDIT_RETENTION_SOURCE_POLICY,
    "cleanup": CLEANUP_SOURCE_POLICY,
    "deletion": DELETION_SOURCE_POLICY,
    "emergency_export": EMERGENCY_EXPORT_SOURCE_POLICY,
    "finalization": FINALIZATION_SOURCE_POLICY,
    "metadata_retention": METADATA_RETENTION_SOURCE_POLICY,
    "retention": RETENTION_SOURCE_POLICY,
})

_DYNAMIC_NODE_TYPES = (
    ast.Assert, ast.AsyncFor, ast.AsyncFunctionDef, ast.AsyncWith, ast.AugAssign,
    ast.Await, ast.Delete, ast.For, ast.Global, ast.Lambda, ast.Match,
    ast.NamedExpr, ast.Nonlocal, ast.Try, ast.TryStar, ast.While, ast.With, ast.Yield,
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


def _dataclass_source_profile_is_exact(
    tree: ast.Module,
    *,
    class_name: str,
    expected_fields: tuple[tuple[str, str], ...],
    expected_false_classvars: tuple[str, ...],
) -> bool:
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
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
    return (
        tuple(fields) == expected_fields
        and tuple(false_classvars) == expected_false_classvars
    )


def _plan_profile_is_exact(
    tree: ast.Module,
    policy: OrchestrationSourcePolicy,
) -> bool:
    profiles: tuple[DataclassIdentity, ...] = (
        (
            policy.plan_class_name,
            policy.plan_fields,
            policy.plan_false_classvars,
        ),
        *policy.additional_dataclasses,
    )
    return all(
        _dataclass_source_profile_is_exact(
            tree,
            class_name=class_name,
            expected_fields=fields,
            expected_false_classvars=false_classvars,
        )
        for class_name, fields, false_classvars in profiles
    )


def _str_enum_source_profile_is_exact(
    tree: ast.Module,
    *,
    class_name: str,
    expected_members: tuple[tuple[str, str], ...],
) -> bool:
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(matches) != 1:
        return False
    enum_class = matches[0]
    if (
        enum_class.decorator_list
        or enum_class.keywords
        or len(enum_class.bases) != 1
        or not isinstance(enum_class.bases[0], ast.Name)
        or enum_class.bases[0].id != "StrEnum"
    ):
        return False
    members: list[tuple[str, str]] = []
    for node in enum_class.body:
        if not (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is str
        ):
            return False
        members.append((node.targets[0].id, node.value.value))
    return tuple(members) == expected_members


def _enum_profiles_are_exact(
    tree: ast.Module,
    policy: OrchestrationSourcePolicy,
) -> bool:
    return all(
        _str_enum_source_profile_is_exact(
            tree,
            class_name=class_name,
            expected_members=members,
        )
        for class_name, members in policy.expected_str_enums
    )


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
    if not _enum_profiles_are_exact(tree, policy):
        violations.append(_violation(code=OrchestrationViolationCode.ENUM_PROFILE_MISMATCH, relative_path=relative_path, line=0, detail_code="STRENUM_MEMBER_PROFILE"))
    if not _executor_profile_is_exact(tree, policy):
        violations.append(_violation(code=OrchestrationViolationCode.EXECUTOR_PROFILE_MISMATCH, relative_path=relative_path, line=0, detail_code="FAIL_CLOSED_EXECUTOR_PROFILE"))

    protected_call_roots = frozenset(
        call_name.partition(".")[0] for call_name in policy.allowed_calls
    )
    protected_imports = frozenset(
        alias or name
        for _, _, names in policy.expected_imports
        for name, alias in names
    )
    protected_members = frozenset(name for _, name in policy.expected_module_members)
    protected_bindings = (
        protected_call_roots | protected_imports | protected_members
    )
    top_level_assignment_targets = frozenset(
        id(target)
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
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
        elif isinstance(node, ast.arg) and node.arg in protected_bindings:
            detail_code = (
                "CALL_NAME_REBOUND"
                if node.arg in protected_call_roots
                else "PROTECTED_NAME_REBOUND"
            )
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code=detail_code))
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and id(node) not in top_level_assignment_targets
            and node.id in protected_bindings
        ):
            detail_code = (
                "CALL_NAME_REBOUND"
                if node.id in protected_call_roots
                else "PROTECTED_NAME_REBOUND"
            )
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code=detail_code))
        elif isinstance(node, ast.Call) and _call_name(node) not in policy.allowed_calls:
            violations.append(_violation(code=OrchestrationViolationCode.CALL_DISALLOWED, relative_path=relative_path, line=node.lineno, detail_code="CALL_NOT_ALLOWLISTED"))
        elif isinstance(node, ast.Raise) and not _raise_is_allowlisted(node, policy):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="RAISE_NOT_ALLOWLISTED"))
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, ast.Store):
            violations.append(_violation(code=OrchestrationViolationCode.DYNAMIC_CONSTRUCT, relative_path=relative_path, line=node.lineno, detail_code="MUTATING_TARGET"))
    return tuple(sorted(set(violations), key=lambda item: (item.relative_path, item.line, item.code.value, item.detail_code)))


def scan_inert_orchestration_sources(*, lifecycle_root: Path, relative_to: Path) -> tuple[OrchestrationSourceViolation, ...]:
    """Scan only the approved inert orchestration source targets."""
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
