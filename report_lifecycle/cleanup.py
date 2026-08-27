"""Pure ciphertext-cleanup timing plans with no destructive capability."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Never
from uuid import UUID

from django.utils import timezone

from .errors import CleanupOrchestrationUnavailable, LifecycleTransitionDenied
from .transitions import MAX_STATE_VERSION


FIRST_RETRY_DELAY = timedelta(seconds=5)
SECOND_RETRY_DELAY = timedelta(seconds=30)
THIRD_RETRY_DELAY = timedelta(minutes=2)
FIRST_HOUR_RETRY_DELAY = timedelta(minutes=5)
FIRST_DAY_RETRY_DELAY = timedelta(hours=1)
LONG_TERM_RETRY_DELAY = timedelta(hours=6)
FIRST_HOUR_BOUNDARY = timedelta(hours=1)
FIRST_DAY_BOUNDARY = timedelta(hours=24)
PERSISTENT_FAILURE_ALERT_DELAY = timedelta(minutes=15)
MAXIMUM_RECONCILER_INTERVAL = timedelta(minutes=1)
MAXIMUM_JITTER_FRACTION = (1, 10)


class CleanupRetryTier(StrEnum):
    FIRST_FIVE_SECONDS = "FIRST_FIVE_SECONDS"
    SECOND_THIRTY_SECONDS = "SECOND_THIRTY_SECONDS"
    THIRD_TWO_MINUTES = "THIRD_TWO_MINUTES"
    FIVE_MINUTES_FIRST_HOUR = "FIVE_MINUTES_FIRST_HOUR"
    HOURLY_THROUGH_FIRST_DAY = "HOURLY_THROUGH_FIRST_DAY"
    SIX_HOURLY_INDEFINITE = "SIX_HOURLY_INDEFINITE"


class CleanupAlertDisposition(StrEnum):
    NOT_DUE = "NOT_DUE"
    SUBMISSION_DUE = "SUBMISSION_DUE"
    RECORDED = "RECORDED"


@dataclass(frozen=True, slots=True)
class CleanupFailureSnapshot:
    cleanup_id: UUID
    idempotency_id: UUID
    failure_count: int
    first_failed_at: datetime
    last_failed_at: datetime
    persistent_alert_recorded_at: datetime | None


@dataclass(frozen=True, slots=True)
class InertCleanupRetryPlan:
    cleanup_id: UUID
    idempotency_id: UUID
    failure_count: int
    first_failed_at: datetime
    last_failed_at: datetime
    observed_at: datetime
    retry_tier: CleanupRetryTier
    base_retry_delay: timedelta
    maximum_jitter: timedelta
    next_base_retry_at: datetime
    persistent_alert_due_at: datetime
    alert_disposition: CleanupAlertDisposition

    authorizes_deletion: ClassVar[bool] = False
    schedules_task: ClassVar[bool] = False
    persists_state: ClassVar[bool] = False
    submits_alert: ClassVar[bool] = False
    calls_external_service: ClassVar[bool] = False


def _require_timestamp(value: object) -> datetime:
    if type(value) is not datetime or not timezone.is_aware(value):
        raise LifecycleTransitionDenied()
    return timezone.localtime(value, timezone=UTC)


def _retry_profile(
    *,
    failure_count: int,
    elapsed_at_last_failure: timedelta,
) -> tuple[CleanupRetryTier, timedelta]:
    if failure_count == 1:
        return CleanupRetryTier.FIRST_FIVE_SECONDS, FIRST_RETRY_DELAY
    if failure_count == 2:
        return CleanupRetryTier.SECOND_THIRTY_SECONDS, SECOND_RETRY_DELAY
    if failure_count == 3:
        return CleanupRetryTier.THIRD_TWO_MINUTES, THIRD_RETRY_DELAY
    if elapsed_at_last_failure < FIRST_HOUR_BOUNDARY:
        return CleanupRetryTier.FIVE_MINUTES_FIRST_HOUR, FIRST_HOUR_RETRY_DELAY
    if elapsed_at_last_failure < FIRST_DAY_BOUNDARY:
        return CleanupRetryTier.HOURLY_THROUGH_FIRST_DAY, FIRST_DAY_RETRY_DELAY
    return CleanupRetryTier.SIX_HOURLY_INDEFINITE, LONG_TERM_RETRY_DELAY


def plan_inert_cleanup_retry(
    *,
    snapshot: CleanupFailureSnapshot,
) -> InertCleanupRetryPlan:
    """Describe retry and alert timing without scheduling or deleting anything."""

    if type(snapshot) is not CleanupFailureSnapshot:
        raise LifecycleTransitionDenied()
    if (
        type(snapshot.cleanup_id) is not UUID
        or type(snapshot.idempotency_id) is not UUID
        or type(snapshot.failure_count) is not int
        or snapshot.failure_count < 1
        or snapshot.failure_count >= MAX_STATE_VERSION
    ):
        raise LifecycleTransitionDenied()

    first_failed_at = _require_timestamp(snapshot.first_failed_at)
    last_failed_at = _require_timestamp(snapshot.last_failed_at)
    observed_at = _require_timestamp(timezone.now())
    if first_failed_at > last_failed_at or last_failed_at > observed_at:
        raise LifecycleTransitionDenied()

    alert_due_at = first_failed_at + PERSISTENT_FAILURE_ALERT_DELAY
    if snapshot.persistent_alert_recorded_at is None:
        alert_recorded_at = None
    else:
        alert_recorded_at = _require_timestamp(
            snapshot.persistent_alert_recorded_at
        )
        if alert_recorded_at < alert_due_at or alert_recorded_at > observed_at:
            raise LifecycleTransitionDenied()

    retry_tier, base_retry_delay = _retry_profile(
        failure_count=snapshot.failure_count,
        elapsed_at_last_failure=last_failed_at - first_failed_at,
    )
    maximum_jitter = (
        base_retry_delay * MAXIMUM_JITTER_FRACTION[0]
        / MAXIMUM_JITTER_FRACTION[1]
    )
    if alert_recorded_at is not None:
        alert_disposition = CleanupAlertDisposition.RECORDED
    elif observed_at >= alert_due_at:
        alert_disposition = CleanupAlertDisposition.SUBMISSION_DUE
    else:
        alert_disposition = CleanupAlertDisposition.NOT_DUE

    return InertCleanupRetryPlan(
        cleanup_id=snapshot.cleanup_id,
        idempotency_id=snapshot.idempotency_id,
        failure_count=snapshot.failure_count,
        first_failed_at=first_failed_at,
        last_failed_at=last_failed_at,
        observed_at=observed_at,
        retry_tier=retry_tier,
        base_retry_delay=base_retry_delay,
        maximum_jitter=maximum_jitter,
        next_base_retry_at=last_failed_at + base_retry_delay,
        persistent_alert_due_at=alert_due_at,
        alert_disposition=alert_disposition,
    )


def execute_cleanup_retry(*, plan: InertCleanupRetryPlan) -> Never:
    """Deny task scheduling, alerting, and deletion until all gates close."""

    if type(plan) is not InertCleanupRetryPlan:
        raise CleanupOrchestrationUnavailable()
    raise CleanupOrchestrationUnavailable()
