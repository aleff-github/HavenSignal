from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from django.utils import timezone

from .errors import LifecycleTransitionDenied
from .states import (
    LeaseState,
    ReportState,
    SecurityOperationState,
    require_lease_transition,
    require_report_transition,
    require_security_operation_transition,
)


MAX_STATE_VERSION = 9_223_372_036_854_775_807
LEASE_IDLE_LIMIT = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class ReportTransitionPlan:
    report_id: UUID
    current_state: ReportState
    current_version: int
    target_state: ReportState
    target_version: int
    changed_at: datetime


@dataclass(frozen=True, slots=True)
class LeaseTransitionPlan:
    lease_id: UUID
    current_state: LeaseState
    current_version: int
    target_state: LeaseState
    target_version: int
    changed_at: datetime


@dataclass(frozen=True, slots=True)
class SecurityOperationTransitionPlan:
    operation_id: UUID
    current_state: SecurityOperationState
    current_version: int
    target_state: SecurityOperationState
    target_version: int
    changed_at: datetime


@dataclass(frozen=True, slots=True)
class LeaseActivityPlan:
    lease_id: UUID
    generation: int
    previous_activity_at: datetime
    next_activity_at: datetime
    absolute_expires_at: datetime


@dataclass(frozen=True, slots=True)
class LeaseGenerationPlan:
    report_id: UUID
    current_generation: int
    next_generation: int
    changed_at: datetime


def _require_uuid(value: object) -> UUID:
    if not isinstance(value, UUID):
        raise LifecycleTransitionDenied()
    return value


def _require_counter(value: object, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value >= MAX_STATE_VERSION
    ):
        raise LifecycleTransitionDenied()
    return value


def _require_timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or timezone.is_naive(value):
        raise LifecycleTransitionDenied()
    return value


def plan_report_transition(
    *,
    report_id: UUID,
    current_state: str | ReportState,
    current_version: int,
    target_state: str | ReportState,
) -> ReportTransitionPlan:
    current, target = require_report_transition(current_state, target_state)
    version = _require_counter(current_version)
    return ReportTransitionPlan(
        report_id=_require_uuid(report_id),
        current_state=current,
        current_version=version,
        target_state=target,
        target_version=version + 1,
        changed_at=timezone.now(),
    )


def plan_lease_transition(
    *,
    lease_id: UUID,
    current_state: str | LeaseState,
    current_version: int,
    target_state: str | LeaseState,
) -> LeaseTransitionPlan:
    current, target = require_lease_transition(current_state, target_state)
    version = _require_counter(current_version)
    return LeaseTransitionPlan(
        lease_id=_require_uuid(lease_id),
        current_state=current,
        current_version=version,
        target_state=target,
        target_version=version + 1,
        changed_at=timezone.now(),
    )


def plan_security_operation_transition(
    *,
    operation_id: UUID,
    current_state: str | SecurityOperationState,
    current_version: int,
    target_state: str | SecurityOperationState,
) -> SecurityOperationTransitionPlan:
    current, target = require_security_operation_transition(
        current_state,
        target_state,
    )
    version = _require_counter(current_version)
    return SecurityOperationTransitionPlan(
        operation_id=_require_uuid(operation_id),
        current_state=current,
        current_version=version,
        target_state=target,
        target_version=version + 1,
        changed_at=timezone.now(),
    )


def plan_lease_activity(
    *,
    lease_id: UUID,
    current_generation: int,
    presented_generation: int,
    opened_at: datetime,
    last_activity_at: datetime,
    absolute_expires_at: datetime,
) -> LeaseActivityPlan:
    """Plan one activity refresh using server time without extending absolute expiry."""

    identifier = _require_uuid(lease_id)
    generation = _require_counter(current_generation, minimum=1)
    presented = _require_counter(presented_generation, minimum=1)
    opened = _require_timestamp(opened_at)
    previous_activity = _require_timestamp(last_activity_at)
    absolute_expiry = _require_timestamp(absolute_expires_at)
    now = timezone.now()

    if (
        presented != generation
        or previous_activity < opened
        or absolute_expiry <= opened
        or previous_activity > now
        or now >= absolute_expiry
        or now - previous_activity >= LEASE_IDLE_LIMIT
    ):
        raise LifecycleTransitionDenied()

    return LeaseActivityPlan(
        lease_id=identifier,
        generation=generation,
        previous_activity_at=previous_activity,
        next_activity_at=now,
        absolute_expires_at=absolute_expiry,
    )


def plan_next_lease_generation(
    *,
    report_id: UUID,
    current_generation: int,
) -> LeaseGenerationPlan:
    """Plan the next monotonic fencing generation without writing the database."""

    generation = _require_counter(current_generation)
    return LeaseGenerationPlan(
        report_id=_require_uuid(report_id),
        current_generation=generation,
        next_generation=generation + 1,
        changed_at=timezone.now(),
    )
