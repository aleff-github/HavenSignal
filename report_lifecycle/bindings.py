from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from uuid import UUID

from django.utils import timezone

from .errors import LifecycleTransitionDenied
from .states import LeaseState, ReportState, SecurityOperationKind
from .transitions import MAX_STATE_VERSION, LeaseActivityPlan, plan_lease_activity


@dataclass(frozen=True, slots=True)
class OperationBindingPolicy:
    required_report_state: ReportState
    requires_active_lease: bool


OPERATION_BINDING_POLICIES = MappingProxyType(
    {
        SecurityOperationKind.REOPEN_REPORT: OperationBindingPolicy(
            required_report_state=ReportState.INTERRUPTED,
            requires_active_lease=False,
        ),
        SecurityOperationKind.FINALIZE_RESPONSE: OperationBindingPolicy(
            required_report_state=ReportState.OPEN,
            requires_active_lease=True,
        ),
        SecurityOperationKind.EMERGENCY_EXPORT: OperationBindingPolicy(
            required_report_state=ReportState.OPEN,
            requires_active_lease=True,
        ),
        SecurityOperationKind.DELETE_REPORT: OperationBindingPolicy(
            required_report_state=ReportState.OPEN,
            requires_active_lease=True,
        ),
        SecurityOperationKind.DELETE_REPORT_FLOOD: OperationBindingPolicy(
            required_report_state=ReportState.SEALED,
            requires_active_lease=False,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ReportBindingSnapshot:
    report_id: UUID
    state: ReportState | str
    state_version: int
    current_lease_generation: int
    active_operator_id: UUID | None


@dataclass(frozen=True, slots=True)
class LeaseBindingSnapshot:
    lease_id: UUID
    report_id: UUID
    operator_id: UUID
    generation: int
    state: LeaseState | str
    state_version: int
    opened_at: datetime
    last_activity_at: datetime
    absolute_expires_at: datetime


@dataclass(frozen=True, slots=True)
class SecurityOperationCommand:
    operation_id: UUID
    idempotency_id: UUID
    kind: SecurityOperationKind | str
    report_id: UUID
    expected_report_version: int
    actor_id: UUID
    lease_id: UUID | None = None
    lease_generation: int | None = None


@dataclass(frozen=True, slots=True)
class ValidatedSecurityOperationBinding:
    command: SecurityOperationCommand
    kind: SecurityOperationKind
    report_state: ReportState
    report_state_version: int
    lease_activity: LeaseActivityPlan | None
    validated_at: datetime


def _require_uuid(value: object) -> UUID:
    if not isinstance(value, UUID):
        raise LifecycleTransitionDenied()
    return value


def _require_optional_uuid(value: object) -> UUID | None:
    if value is None:
        return None
    return _require_uuid(value)


def _require_counter(value: object, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value >= MAX_STATE_VERSION
    ):
        raise LifecycleTransitionDenied()
    return value


def _require_operation_kind(value: object) -> SecurityOperationKind:
    try:
        return SecurityOperationKind(value)
    except (TypeError, ValueError) as error:
        raise LifecycleTransitionDenied() from error


def _require_report_state(value: object) -> ReportState:
    try:
        return ReportState(value)
    except (TypeError, ValueError) as error:
        raise LifecycleTransitionDenied() from error


def _require_lease_state(value: object) -> LeaseState:
    try:
        return LeaseState(value)
    except (TypeError, ValueError) as error:
        raise LifecycleTransitionDenied() from error


def _require_no_lease_binding(
    *,
    command: SecurityOperationCommand,
    lease: LeaseBindingSnapshot | None,
) -> None:
    if (
        command.lease_id is not None
        or command.lease_generation is not None
        or lease is not None
    ):
        raise LifecycleTransitionDenied()


def _validate_active_lease_binding(
    *,
    command: SecurityOperationCommand,
    report: ReportBindingSnapshot,
    lease: LeaseBindingSnapshot | None,
) -> LeaseActivityPlan:
    if lease is None:
        raise LifecycleTransitionDenied()

    command_lease_id = _require_optional_uuid(command.lease_id)
    if command_lease_id is None:
        raise LifecycleTransitionDenied()
    command_generation = _require_counter(command.lease_generation, minimum=1)
    lease_generation = _require_counter(lease.generation, minimum=1)
    report_generation = _require_counter(report.current_lease_generation)
    _require_counter(lease.state_version)

    if (
        _require_lease_state(lease.state) != LeaseState.ACTIVE
        or _require_uuid(lease.lease_id) != command_lease_id
        or _require_uuid(lease.report_id) != _require_uuid(report.report_id)
        or _require_uuid(lease.operator_id) != _require_uuid(command.actor_id)
        or command_generation != lease_generation
        or report_generation != lease_generation
    ):
        raise LifecycleTransitionDenied()

    return plan_lease_activity(
        lease_id=lease.lease_id,
        current_generation=lease_generation,
        presented_generation=command_generation,
        opened_at=lease.opened_at,
        last_activity_at=lease.last_activity_at,
        absolute_expires_at=lease.absolute_expires_at,
    )


def validate_inert_security_operation_binding(
    *,
    command: SecurityOperationCommand,
    report: ReportBindingSnapshot,
    lease: LeaseBindingSnapshot | None,
) -> ValidatedSecurityOperationBinding:
    """Validate metadata bindings only; this never authorizes a protected action."""

    operation_id = _require_uuid(command.operation_id)
    idempotency_id = _require_uuid(command.idempotency_id)
    command_report_id = _require_uuid(command.report_id)
    report_id = _require_uuid(report.report_id)
    actor_id = _require_uuid(command.actor_id)
    expected_report_version = _require_counter(command.expected_report_version)
    report_version = _require_counter(report.state_version)
    _require_counter(report.current_lease_generation)
    active_operator_id = _require_optional_uuid(report.active_operator_id)
    kind = _require_operation_kind(command.kind)
    report_state = _require_report_state(report.state)
    policy = OPERATION_BINDING_POLICIES[kind]

    if (
        command_report_id != report_id
        or expected_report_version != report_version
        or report_state != policy.required_report_state
    ):
        raise LifecycleTransitionDenied()

    lease_activity = None
    if policy.requires_active_lease:
        if active_operator_id != actor_id:
            raise LifecycleTransitionDenied()
        lease_activity = _validate_active_lease_binding(
            command=command,
            report=report,
            lease=lease,
        )
        validated_at = lease_activity.next_activity_at
    else:
        if active_operator_id is not None:
            raise LifecycleTransitionDenied()
        _require_no_lease_binding(command=command, lease=lease)
        validated_at = timezone.now()

    normalized_command = SecurityOperationCommand(
        operation_id=operation_id,
        idempotency_id=idempotency_id,
        kind=kind,
        report_id=command_report_id,
        expected_report_version=expected_report_version,
        actor_id=actor_id,
        lease_id=command.lease_id,
        lease_generation=command.lease_generation,
    )
    return ValidatedSecurityOperationBinding(
        command=normalized_command,
        kind=kind,
        report_state=report_state,
        report_state_version=report_version,
        lease_activity=lease_activity,
        validated_at=validated_at,
    )
