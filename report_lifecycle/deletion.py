"""Pure sequence contract and unavailable executor for operator deletion Stage A."""

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
    DeletionOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from .states import ReportState, SecurityOperationKind
from .transitions import LeaseActivityPlan, MAX_STATE_VERSION


class OperatorDeletionCheckpoint(StrEnum):
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    OPEN_CONTEXT_INPUTS_AND_CAPTCHA_VALIDATED = (
        "OPEN_CONTEXT_INPUTS_AND_CAPTCHA_VALIDATED"
    )
    STEP_UP_AUTHORIZATION_VERIFIED = "STEP_UP_AUTHORIZATION_VERIFIED"
    DELETION_REQUEST_AUDITED = "DELETION_REQUEST_AUDITED"
    LOCKED_CONTEXT_REVALIDATED = "LOCKED_CONTEXT_REVALIDATED"
    DELETING_COMMITTED = "DELETING_COMMITTED"
    ORDINARY_CAPABILITIES_INVALIDATED = "ORDINARY_CAPABILITIES_INVALIDATED"
    REPORT_KEY_DESTRUCTION_CONFIRMED = "REPORT_KEY_DESTRUCTION_CONFIRMED"
    DESTRUCTION_OUTCOME_AUDITED = "DESTRUCTION_OUTCOME_AUDITED"
    RECOVERY_ELIGIBILITY_INVALIDATED = "RECOVERY_ELIGIBILITY_INVALIDATED"
    TERMINAL_STATE_AND_CLEANUP_STARTED = "TERMINAL_STATE_AND_CLEANUP_STARTED"


OPERATOR_DELETION_SEQUENCE = tuple(OperatorDeletionCheckpoint)

OPERATOR_DELETION_TRANSITIONS = MappingProxyType(
    {
        checkpoint: frozenset(
            {OPERATOR_DELETION_SEQUENCE[index + 1]}
            if index + 1 < len(OPERATOR_DELETION_SEQUENCE)
            else set()
        )
        for index, checkpoint in enumerate(OPERATOR_DELETION_SEQUENCE)
    }
)


@dataclass(frozen=True, slots=True)
class InertOperatorDeletionStepPlan:
    operation_id: UUID
    idempotency_id: UUID
    report_id: UUID
    operator_id: UUID
    lease_id: UUID
    report_state_version: int
    lease_generation: int
    source_checkpoint: OperatorDeletionCheckpoint
    target_checkpoint: OperatorDeletionCheckpoint

    authorizes_execution: ClassVar[bool] = False
    persists_checkpoint: ClassVar[bool] = False
    destroys_key_or_content: ClassVar[bool] = False


def _valid_counter(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < MAX_STATE_VERSION


def _require_operator_deletion_binding(
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
        and binding.kind is SecurityOperationKind.DELETE_REPORT
        and command.kind is SecurityOperationKind.DELETE_REPORT
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


def plan_inert_operator_deletion_step(
    *,
    binding: ValidatedSecurityOperationBinding,
    source_checkpoint: OperatorDeletionCheckpoint,
    target_checkpoint: OperatorDeletionCheckpoint,
) -> InertOperatorDeletionStepPlan:
    """Plan one exact sequence edge; the result never authorizes deletion."""

    command, activity = _require_operator_deletion_binding(binding)
    if (
        type(source_checkpoint) is not OperatorDeletionCheckpoint
        or type(target_checkpoint) is not OperatorDeletionCheckpoint
        or target_checkpoint not in OPERATOR_DELETION_TRANSITIONS[source_checkpoint]
    ):
        raise LifecycleTransitionDenied()
    return InertOperatorDeletionStepPlan(
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


def execute_operator_deletion_step(*, plan: InertOperatorDeletionStepPlan) -> Never:
    """Deny every destructive action until all dependent gates are closed."""

    if type(plan) is not InertOperatorDeletionStepPlan:
        raise DeletionOrchestrationUnavailable()
    raise DeletionOrchestrationUnavailable()
