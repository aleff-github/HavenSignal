"""Pure sequence contract and unavailable executor for finalization Stage A."""

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
    FinalizationOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from .states import ReportState, SecurityOperationKind
from .transitions import LeaseActivityPlan, MAX_STATE_VERSION


class FinalizationCheckpoint(StrEnum):
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    OPEN_CONTEXT_VALIDATED = "OPEN_CONTEXT_VALIDATED"
    CAPTCHA_VALIDATED = "CAPTCHA_VALIDATED"
    STEP_UP_CONSUMED = "STEP_UP_CONSUMED"
    FINALIZATION_REQUEST_AUDITED = "FINALIZATION_REQUEST_AUDITED"
    STAGED_AND_FINALIZING_COMMITTED = "STAGED_AND_FINALIZING_COMMITTED"
    STAGING_DURABILITY_VERIFIED = "STAGING_DURABILITY_VERIFIED"
    REPORT_KEY_DESTRUCTION_REQUESTED = "REPORT_KEY_DESTRUCTION_REQUESTED"
    REPORT_KEY_DESTRUCTION_CONFIRMED = "REPORT_KEY_DESTRUCTION_CONFIRMED"
    REPORT_KEY_DESTRUCTION_AUDITED = "REPORT_KEY_DESTRUCTION_AUDITED"
    RESPONSE_AVAILABLE_PUBLISHED = "RESPONSE_AVAILABLE_PUBLISHED"
    LEASE_CAPABILITIES_INVALIDATED = "LEASE_CAPABILITIES_INVALIDATED"
    CIPHERTEXT_DELETION_STARTED = "CIPHERTEXT_DELETION_STARTED"


FINALIZATION_SEQUENCE = (
    FinalizationCheckpoint.REQUEST_RECEIVED,
    FinalizationCheckpoint.OPEN_CONTEXT_VALIDATED,
    FinalizationCheckpoint.CAPTCHA_VALIDATED,
    FinalizationCheckpoint.STEP_UP_CONSUMED,
    FinalizationCheckpoint.FINALIZATION_REQUEST_AUDITED,
    FinalizationCheckpoint.STAGED_AND_FINALIZING_COMMITTED,
    FinalizationCheckpoint.STAGING_DURABILITY_VERIFIED,
    FinalizationCheckpoint.REPORT_KEY_DESTRUCTION_REQUESTED,
    FinalizationCheckpoint.REPORT_KEY_DESTRUCTION_CONFIRMED,
    FinalizationCheckpoint.REPORT_KEY_DESTRUCTION_AUDITED,
    FinalizationCheckpoint.RESPONSE_AVAILABLE_PUBLISHED,
    FinalizationCheckpoint.LEASE_CAPABILITIES_INVALIDATED,
    FinalizationCheckpoint.CIPHERTEXT_DELETION_STARTED,
)

FINALIZATION_TRANSITIONS = MappingProxyType(
    {
        checkpoint: frozenset(
            {FINALIZATION_SEQUENCE[index + 1]}
            if index + 1 < len(FINALIZATION_SEQUENCE)
            else set()
        )
        for index, checkpoint in enumerate(FINALIZATION_SEQUENCE)
    }
)


@dataclass(frozen=True, slots=True)
class InertFinalizationStepPlan:
    operation_id: UUID
    report_id: UUID
    operator_id: UUID
    lease_id: UUID
    report_state_version: int
    lease_generation: int
    source_checkpoint: FinalizationCheckpoint
    target_checkpoint: FinalizationCheckpoint

    authorizes_execution: ClassVar[bool] = False
    persists_checkpoint: ClassVar[bool] = False


def _valid_counter(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < MAX_STATE_VERSION


def _require_finalization_binding(
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
        and type(command.report_id) is UUID
        and type(command.actor_id) is UUID
        and type(command.lease_id) is UUID
        and type(activity.lease_id) is UUID
        and command.lease_id == activity.lease_id
        and binding.kind is SecurityOperationKind.FINALIZE_RESPONSE
        and command.kind is SecurityOperationKind.FINALIZE_RESPONSE
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


def plan_inert_finalization_step(
    *,
    binding: ValidatedSecurityOperationBinding,
    source_checkpoint: FinalizationCheckpoint,
    target_checkpoint: FinalizationCheckpoint,
) -> InertFinalizationStepPlan:
    """Plan one exact sequence edge; the result never authorizes execution."""

    command, activity = _require_finalization_binding(binding)
    if (
        type(source_checkpoint) is not FinalizationCheckpoint
        or type(target_checkpoint) is not FinalizationCheckpoint
        or target_checkpoint not in FINALIZATION_TRANSITIONS[source_checkpoint]
    ):
        raise LifecycleTransitionDenied()
    return InertFinalizationStepPlan(
        operation_id=command.operation_id,
        report_id=command.report_id,
        operator_id=command.actor_id,
        lease_id=activity.lease_id,
        report_state_version=binding.report_state_version,
        lease_generation=activity.generation,
        source_checkpoint=source_checkpoint,
        target_checkpoint=target_checkpoint,
    )


def execute_finalization_step(*, plan: InertFinalizationStepPlan) -> Never:
    """Deny every protected action until all dependent gates are closed."""

    if type(plan) is not InertFinalizationStepPlan:
        raise FinalizationOrchestrationUnavailable()
    raise FinalizationOrchestrationUnavailable()
