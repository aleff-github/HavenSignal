"""Pure sequence contract and unavailable Emergency Export executor."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar, Never
from uuid import UUID

from django.utils import timezone

from .bindings import (
    SecurityOperationCommand,
    ValidatedSecurityOperationBinding,
)
from .errors import (
    EmergencyExportOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from .states import ReportState, SecurityOperationKind
from .transitions import LeaseActivityPlan, MAX_STATE_VERSION


class EmergencyExportCheckpoint(StrEnum):
    CONTEXT_VALIDATED = "CONTEXT_VALIDATED"
    REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED = (
        "REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED"
    )
    REQUESTED_AUDIT_RECEIPT_OBTAINED = "REQUESTED_AUDIT_RECEIPT_OBTAINED"
    ADMINISTRATOR_ALERT_ACCEPTED = "ADMINISTRATOR_ALERT_ACCEPTED"
    AUTHORIZED_JOB_AND_FENCE_COMMITTED = "AUTHORIZED_JOB_AND_FENCE_COMMITTED"
    AUTHORIZED_AUDIT_ACCEPTED = "AUTHORIZED_AUDIT_ACCEPTED"
    ENCRYPTED_STAGING_CREATED = "ENCRYPTED_STAGING_CREATED"
    ENCRYPTED_STAGING_VERIFIED = "ENCRYPTED_STAGING_VERIFIED"
    COMPLETED_AUDIT_RECEIPT_OBTAINED = "COMPLETED_AUDIT_RECEIPT_OBTAINED"
    DELIVERY_CONTEXT_REVALIDATED = "DELIVERY_CONTEXT_REVALIDATED"
    DELIVERY_CONSUMED_AND_CLEANUP_STARTED = (
        "DELIVERY_CONSUMED_AND_CLEANUP_STARTED"
    )


EMERGENCY_EXPORT_SEQUENCE = tuple(EmergencyExportCheckpoint)

EMERGENCY_EXPORT_TRANSITIONS = MappingProxyType(
    {
        checkpoint: frozenset(
            {EMERGENCY_EXPORT_SEQUENCE[index + 1]}
            if index + 1 < len(EMERGENCY_EXPORT_SEQUENCE)
            else set()
        )
        for index, checkpoint in enumerate(EMERGENCY_EXPORT_SEQUENCE)
    }
)


@dataclass(frozen=True, slots=True)
class InertEmergencyExportStepPlan:
    operation_id: UUID
    idempotency_id: UUID
    report_id: UUID
    operator_id: UUID
    lease_id: UUID
    report_state_version: int
    lease_generation: int
    source_checkpoint: EmergencyExportCheckpoint
    target_checkpoint: EmergencyExportCheckpoint

    authorizes_execution: ClassVar[bool] = False
    persists_checkpoint: ClassVar[bool] = False
    creates_export_artifact: ClassVar[bool] = False
    releases_plaintext: ClassVar[bool] = False


def _valid_counter(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < MAX_STATE_VERSION


def _require_emergency_export_binding(
    binding: ValidatedSecurityOperationBinding,
) -> tuple[SecurityOperationCommand, LeaseActivityPlan]:
    if type(binding) is not ValidatedSecurityOperationBinding:
        raise LifecycleTransitionDenied()
    command = binding.command
    activity = binding.lease_activity
    if not (
        type(command) is SecurityOperationCommand
        and type(activity) is LeaseActivityPlan
        and type(command.operation_id) is UUID
        and type(command.idempotency_id) is UUID
        and type(command.report_id) is UUID
        and type(command.actor_id) is UUID
        and type(command.lease_id) is UUID
        and type(activity.lease_id) is UUID
        and command.lease_id == activity.lease_id
        and binding.kind is SecurityOperationKind.EMERGENCY_EXPORT
        and command.kind is SecurityOperationKind.EMERGENCY_EXPORT
        and binding.report_state is ReportState.OPEN
        and _valid_counter(binding.report_state_version)
        and _valid_counter(command.expected_report_version)
        and binding.report_state_version == command.expected_report_version
        and _valid_counter(command.lease_generation, minimum=1)
        and _valid_counter(activity.generation, minimum=1)
        and command.lease_generation == activity.generation
        and type(binding.validated_at) is datetime
        and type(activity.previous_activity_at) is datetime
        and type(activity.next_activity_at) is datetime
        and type(activity.absolute_expires_at) is datetime
        and timezone.is_aware(binding.validated_at)
        and timezone.is_aware(activity.previous_activity_at)
        and timezone.is_aware(activity.next_activity_at)
        and timezone.is_aware(activity.absolute_expires_at)
        and binding.validated_at == activity.next_activity_at
        and activity.previous_activity_at <= activity.next_activity_at
        and activity.next_activity_at < activity.absolute_expires_at
    ):
        raise LifecycleTransitionDenied()
    return command, activity


def plan_inert_emergency_export_step(
    *,
    binding: ValidatedSecurityOperationBinding,
    source_checkpoint: EmergencyExportCheckpoint,
    target_checkpoint: EmergencyExportCheckpoint,
) -> InertEmergencyExportStepPlan:
    """Plan one exact sequence edge without authorizing an export."""

    command, activity = _require_emergency_export_binding(binding)
    if (
        type(source_checkpoint) is not EmergencyExportCheckpoint
        or type(target_checkpoint) is not EmergencyExportCheckpoint
        or target_checkpoint not in EMERGENCY_EXPORT_TRANSITIONS[source_checkpoint]
    ):
        raise LifecycleTransitionDenied()
    return InertEmergencyExportStepPlan(
        operation_id=command.operation_id,
        idempotency_id=command.idempotency_id,
        report_id=command.report_id,
        operator_id=command.actor_id,
        lease_id=activity.lease_id,
        report_state_version=binding.report_state_version,
        lease_generation=activity.generation,
        source_checkpoint=source_checkpoint,
        target_checkpoint=target_checkpoint,
    )


def execute_emergency_export_step(*, plan: InertEmergencyExportStepPlan) -> Never:
    """Deny export execution until every dependent gate is closed."""

    if type(plan) is not InertEmergencyExportStepPlan:
        raise EmergencyExportOrchestrationUnavailable()
    raise EmergencyExportOrchestrationUnavailable()
