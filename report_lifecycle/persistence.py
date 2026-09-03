from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, connections, transaction
from django.db.models import Max
from django.utils import timezone

from .bindings import (
    LeaseBindingSnapshot,
    ReportBindingSnapshot,
    SecurityOperationCommand,
    ValidatedSecurityOperationBinding,
    validate_inert_security_operation_binding,
)
from .errors import LifecyclePersistenceUnavailable, LifecycleTransitionDenied
from .models import Report, ReportLease, SecurityOperation
from .states import SecurityOperationState
from .transitions import MAX_STATE_VERSION, plan_security_operation_transition


@dataclass(frozen=True, slots=True)
class LifecycleBackendCapabilities:
    alias: str
    vendor: str
    supports_transactions: bool
    supports_row_locks: bool
    supports_partial_indexes: bool


@dataclass(frozen=True, slots=True)
class PreparedSecurityOperation:
    operation_id: UUID
    report_id: UUID
    idempotency_id: UUID
    state: SecurityOperationState
    bound_report_version: int
    fence_token: int
    lease_id: UUID | None
    lease_generation: int | None


@dataclass(frozen=True, slots=True)
class ActivatedSecurityOperation:
    operation_id: UUID
    report_id: UUID
    idempotency_id: UUID
    state: SecurityOperationState
    state_version: int
    bound_report_version: int
    fence_token: int
    lease_id: UUID | None
    lease_generation: int | None
    activated_at: datetime


@dataclass(frozen=True, slots=True)
class AbortedSecurityOperation:
    operation_id: UUID
    report_id: UUID
    idempotency_id: UUID
    state: SecurityOperationState
    state_version: int
    bound_report_version: int
    fence_token: int
    lease_id: UUID | None
    lease_generation: int | None
    terminal_at: datetime


def inspect_lifecycle_backend(*, using: str = "default") -> LifecycleBackendCapabilities:
    connection = connections[using]
    return LifecycleBackendCapabilities(
        alias=using,
        vendor=connection.vendor,
        supports_transactions=connection.features.supports_transactions,
        supports_row_locks=connection.features.has_select_for_update,
        supports_partial_indexes=connection.features.supports_partial_indexes,
    )


def require_postgresql_transition_backend(
    *,
    using: str = "default",
) -> LifecycleBackendCapabilities:
    if type(using) is not str or not using:
        raise LifecyclePersistenceUnavailable()
    try:
        capabilities = inspect_lifecycle_backend(using=using)
    except Exception:
        raise LifecyclePersistenceUnavailable() from None
    if (
        capabilities.vendor != "postgresql"
        or not capabilities.supports_transactions
        or not capabilities.supports_row_locks
        or not capabilities.supports_partial_indexes
    ):
        raise LifecyclePersistenceUnavailable()
    return capabilities


def persist_validated_security_operation(
    *,
    binding: ValidatedSecurityOperationBinding,
    using: str = "default",
) -> PreparedSecurityOperation:
    """Atomically prepare metadata only; never execute a protected operation."""

    if (
        type(binding) is not ValidatedSecurityOperationBinding
        or type(binding.command) is not SecurityOperationCommand
        or type(using) is not str
        or not using
    ):
        raise LifecyclePersistenceUnavailable()
    require_postgresql_transition_backend(using=using)
    if connections[using].vendor != "postgresql":
        raise LifecyclePersistenceUnavailable()

    try:
        with transaction.atomic(using=using):
            command = binding.command
            report = (
                Report.objects.using(using)
                .select_for_update()
                .get(id=command.report_id)
            )
            lease = _lock_optional_lease(
                command=command,
                report=report,
                using=using,
            )
            revalidated = validate_inert_security_operation_binding(
                command=command,
                report=_report_snapshot(report),
                lease=_lease_snapshot(lease),
            )
            if not _binding_matches_revalidated(
                binding=binding,
                revalidated=revalidated,
            ):
                raise LifecyclePersistenceUnavailable()
            if SecurityOperation.objects.using(using).filter(
                report=report,
                state__in=(
                    SecurityOperationState.PREPARED,
                    SecurityOperationState.ACTIVE,
                ),
            ).exists():
                raise LifecyclePersistenceUnavailable()

            maximum_fence = (
                SecurityOperation.objects.using(using)
                .filter(report=report)
                .aggregate(maximum=Max("fence_token"))["maximum"]
                or 0
            )
            if maximum_fence >= MAX_STATE_VERSION:
                raise LifecyclePersistenceUnavailable()
            operation = SecurityOperation.objects.using(using).create(
                id=command.operation_id,
                report=report,
                kind=revalidated.kind,
                bound_report_version=report.state_version,
                fence_token=maximum_fence + 1,
                idempotency_id=command.idempotency_id,
                actor_id=command.actor_id,
                lease=lease,
                lease_generation=(lease.generation if lease is not None else None),
            )
            return _prepared_result(operation)
    except LifecyclePersistenceUnavailable:
        raise
    except (
        DatabaseError,
        LifecycleTransitionDenied,
        ObjectDoesNotExist,
        TypeError,
        ValueError,
    ):
        raise LifecyclePersistenceUnavailable() from None


def load_prepared_security_operation(
    *,
    operation_id: UUID,
    using: str = "default",
) -> PreparedSecurityOperation:
    """Rehydrate content-free prepared metadata after database reconnection."""

    if type(operation_id) is not UUID or type(using) is not str or not using:
        raise LifecyclePersistenceUnavailable()
    require_postgresql_transition_backend(using=using)
    if connections[using].vendor != "postgresql":
        raise LifecyclePersistenceUnavailable()

    try:
        with transaction.atomic(using=using):
            operation = SecurityOperation.objects.using(using).get(id=operation_id)
            if not _is_prepared_operation(operation):
                raise LifecyclePersistenceUnavailable()
            return _prepared_result(operation)
    except LifecyclePersistenceUnavailable:
        raise
    except (
        DatabaseError,
        ObjectDoesNotExist,
        TypeError,
        ValueError,
    ):
        raise LifecyclePersistenceUnavailable() from None


def activate_prepared_security_operation(
    *,
    binding: ValidatedSecurityOperationBinding,
    prepared: PreparedSecurityOperation,
    using: str = "default",
) -> ActivatedSecurityOperation:
    """Activate reviewed metadata only; never execute the protected operation."""

    if (
        type(binding) is not ValidatedSecurityOperationBinding
        or type(binding.command) is not SecurityOperationCommand
        or type(prepared) is not PreparedSecurityOperation
        or type(using) is not str
        or not using
    ):
        raise LifecyclePersistenceUnavailable()
    require_postgresql_transition_backend(using=using)
    if connections[using].vendor != "postgresql":
        raise LifecyclePersistenceUnavailable()

    try:
        with transaction.atomic(using=using):
            command = binding.command
            report = (
                Report.objects.using(using)
                .select_for_update()
                .get(id=command.report_id)
            )
            lease = _lock_optional_lease(
                command=command,
                report=report,
                using=using,
            )
            operation = (
                SecurityOperation.objects.using(using)
                .select_for_update()
                .get(id=command.operation_id, report=report)
            )
            revalidated = validate_inert_security_operation_binding(
                command=command,
                report=_report_snapshot(report),
                lease=_lease_snapshot(lease),
            )
            if (
                not _binding_matches_revalidated(
                    binding=binding,
                    revalidated=revalidated,
                )
                or not _prepared_matches_operation(
                    prepared=prepared,
                    operation=operation,
                    revalidated=revalidated,
                )
            ):
                raise LifecyclePersistenceUnavailable()
            transition = plan_security_operation_transition(
                operation_id=operation.id,
                current_state=operation.state,
                current_version=operation.state_version,
                target_state=SecurityOperationState.ACTIVE,
            )
            updated = (
                SecurityOperation.objects.using(using)
                .filter(
                    id=operation.id,
                    state=transition.current_state,
                    state_version=transition.current_version,
                    activated_at__isnull=True,
                    terminal_at__isnull=True,
                )
                .update(
                    state=transition.target_state,
                    state_version=transition.target_version,
                    activated_at=transition.changed_at,
                )
            )
            if updated != 1:
                raise LifecyclePersistenceUnavailable()
            return ActivatedSecurityOperation(
                operation_id=operation.id,
                report_id=report.id,
                idempotency_id=operation.idempotency_id,
                state=transition.target_state,
                state_version=transition.target_version,
                bound_report_version=operation.bound_report_version,
                fence_token=operation.fence_token,
                lease_id=operation.lease_id,
                lease_generation=operation.lease_generation,
                activated_at=transition.changed_at,
            )
    except LifecyclePersistenceUnavailable:
        raise
    except (
        DatabaseError,
        LifecycleTransitionDenied,
        ObjectDoesNotExist,
        TypeError,
        ValueError,
    ):
        raise LifecyclePersistenceUnavailable() from None


def abort_prepared_security_operation(
    *,
    binding: ValidatedSecurityOperationBinding,
    prepared: PreparedSecurityOperation,
    using: str = "default",
) -> AbortedSecurityOperation:
    """Abort prepared metadata only; never interrupt an active operation."""

    if (
        type(binding) is not ValidatedSecurityOperationBinding
        or type(binding.command) is not SecurityOperationCommand
        or type(prepared) is not PreparedSecurityOperation
        or type(using) is not str
        or not using
    ):
        raise LifecyclePersistenceUnavailable()
    require_postgresql_transition_backend(using=using)
    if connections[using].vendor != "postgresql":
        raise LifecyclePersistenceUnavailable()

    try:
        with transaction.atomic(using=using):
            command = binding.command
            report = (
                Report.objects.using(using)
                .select_for_update()
                .get(id=command.report_id)
            )
            lease = _lock_optional_lease(
                command=command,
                report=report,
                using=using,
            )
            operation = (
                SecurityOperation.objects.using(using)
                .select_for_update()
                .get(id=command.operation_id, report=report)
            )
            revalidated = validate_inert_security_operation_binding(
                command=command,
                report=_report_snapshot(report),
                lease=_lease_snapshot(lease),
            )
            if (
                not _binding_matches_revalidated(
                    binding=binding,
                    revalidated=revalidated,
                )
                or not _prepared_matches_operation(
                    prepared=prepared,
                    operation=operation,
                    revalidated=revalidated,
                )
            ):
                raise LifecyclePersistenceUnavailable()
            transition = plan_security_operation_transition(
                operation_id=operation.id,
                current_state=operation.state,
                current_version=operation.state_version,
                target_state=SecurityOperationState.ABORTED,
            )
            updated = (
                SecurityOperation.objects.using(using)
                .filter(
                    id=operation.id,
                    state=transition.current_state,
                    state_version=transition.current_version,
                    activated_at__isnull=True,
                    terminal_at__isnull=True,
                )
                .update(
                    state=transition.target_state,
                    state_version=transition.target_version,
                    terminal_at=transition.changed_at,
                )
            )
            if updated != 1:
                raise LifecyclePersistenceUnavailable()
            return AbortedSecurityOperation(
                operation_id=operation.id,
                report_id=report.id,
                idempotency_id=operation.idempotency_id,
                state=transition.target_state,
                state_version=transition.target_version,
                bound_report_version=operation.bound_report_version,
                fence_token=operation.fence_token,
                lease_id=operation.lease_id,
                lease_generation=operation.lease_generation,
                terminal_at=transition.changed_at,
            )
    except LifecyclePersistenceUnavailable:
        raise
    except (
        DatabaseError,
        LifecycleTransitionDenied,
        ObjectDoesNotExist,
        TypeError,
        ValueError,
    ):
        raise LifecyclePersistenceUnavailable() from None


def _lock_optional_lease(
    *,
    command: SecurityOperationCommand,
    report: Report,
    using: str,
) -> ReportLease | None:
    if command.lease_id is None:
        return None
    return (
        ReportLease.objects.using(using)
        .select_for_update()
        .get(id=command.lease_id, report=report)
    )


def _report_snapshot(report: Report) -> ReportBindingSnapshot:
    return ReportBindingSnapshot(
        report_id=report.id,
        state=report.state,
        state_version=report.state_version,
        current_lease_generation=report.current_lease_generation,
        active_operator_id=report.active_operator_id,
    )


def _lease_snapshot(lease: ReportLease | None) -> LeaseBindingSnapshot | None:
    if lease is None:
        return None
    return LeaseBindingSnapshot(
        lease_id=lease.id,
        report_id=lease.report_id,
        operator_id=lease.operator_id,
        generation=lease.generation,
        state=lease.state,
        state_version=lease.state_version,
        opened_at=lease.opened_at,
        last_activity_at=lease.last_activity_at,
        absolute_expires_at=lease.absolute_expires_at,
    )


def _binding_matches_revalidated(
    *,
    binding: ValidatedSecurityOperationBinding,
    revalidated: ValidatedSecurityOperationBinding,
) -> bool:
    if (
        binding.command != revalidated.command
        or binding.kind is not revalidated.kind
        or binding.report_state is not revalidated.report_state
        or binding.report_state_version != revalidated.report_state_version
        or not timezone.is_aware(binding.validated_at)
        or binding.validated_at > revalidated.validated_at
    ):
        return False
    if binding.lease_activity is None or revalidated.lease_activity is None:
        return binding.lease_activity is revalidated.lease_activity
    return (
        binding.lease_activity.lease_id == revalidated.lease_activity.lease_id
        and binding.lease_activity.generation
        == revalidated.lease_activity.generation
        and binding.lease_activity.previous_activity_at
        == revalidated.lease_activity.previous_activity_at
        and binding.lease_activity.absolute_expires_at
        == revalidated.lease_activity.absolute_expires_at
    )


def _prepared_matches_operation(
    *,
    prepared: PreparedSecurityOperation,
    operation: SecurityOperation,
    revalidated: ValidatedSecurityOperationBinding,
) -> bool:
    command = revalidated.command
    return (
        operation.id == command.operation_id == prepared.operation_id
        and operation.report_id == command.report_id == prepared.report_id
        and operation.idempotency_id
        == command.idempotency_id
        == prepared.idempotency_id
        and operation.kind == revalidated.kind
        and operation.actor_id == command.actor_id
        and operation.state == SecurityOperationState.PREPARED
        and prepared.state is SecurityOperationState.PREPARED
        and operation.state_version == 0
        and operation.bound_report_version
        == revalidated.report_state_version
        == prepared.bound_report_version
        and operation.fence_token == prepared.fence_token
        and operation.lease_id == command.lease_id == prepared.lease_id
        and operation.lease_generation
        == command.lease_generation
        == prepared.lease_generation
        and operation.activated_at is None
        and operation.terminal_at is None
    )


def _is_prepared_operation(operation: SecurityOperation) -> bool:
    return (
        operation.state == SecurityOperationState.PREPARED
        and operation.state_version == 0
        and operation.activated_at is None
        and operation.terminal_at is None
    )


def _prepared_result(operation: SecurityOperation) -> PreparedSecurityOperation:
    return PreparedSecurityOperation(
        operation_id=operation.id,
        report_id=operation.report_id,
        idempotency_id=operation.idempotency_id,
        state=SecurityOperationState(operation.state),
        bound_report_version=operation.bound_report_version,
        fence_token=operation.fence_token,
        lease_id=operation.lease_id,
        lease_generation=operation.lease_generation,
    )
