"""Pure response-retention planning with no protected capability."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Never
from uuid import UUID

from django.utils import timezone

from .errors import (
    LifecycleTransitionDenied,
    ResponseRetentionOrchestrationUnavailable,
)
from .states import ReportState
from .transitions import MAX_STATE_VERSION


UNREAD_RESPONSE_LIMIT = timedelta(hours=90 * 24)
READ_RESPONSE_LIMIT = timedelta(hours=72)


class ResponseRetentionDisposition(StrEnum):
    UNREAD_WINDOW_OPEN = "UNREAD_WINDOW_OPEN"
    READ_WINDOW_OPEN = "READ_WINDOW_OPEN"
    UNREAD_EXPIRY_DUE = "UNREAD_EXPIRY_DUE"
    READ_EXPIRY_DUE = "READ_EXPIRY_DUE"


@dataclass(frozen=True, slots=True)
class ResponseRetentionSnapshot:
    report_id: UUID
    response_id: UUID
    report_state: ReportState
    state_version: int
    response_available_at: datetime
    unread_expires_at: datetime
    first_read_at: datetime | None
    response_expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class InertResponseRetentionPlan:
    report_id: UUID
    response_id: UUID
    report_state: ReportState
    state_version: int
    observed_at: datetime
    unread_expires_at: datetime
    first_read_at: datetime | None
    response_expires_at: datetime | None
    disposition: ResponseRetentionDisposition

    authorizes_recovery: ClassVar[bool] = False
    persists_deadline: ClassVar[bool] = False
    decrypts_response: ClassVar[bool] = False
    destroys_key_or_content: ClassVar[bool] = False


def _require_timestamp(value: object) -> datetime:
    if type(value) is not datetime or not timezone.is_aware(value):
        raise LifecycleTransitionDenied()
    return value


def _elapsed_deadline(value: datetime, *, limit: timedelta) -> datetime:
    return timezone.localtime(value, timezone=UTC) + limit


def _require_snapshot(
    snapshot: object,
) -> tuple[
    ResponseRetentionSnapshot,
    datetime,
    datetime,
    datetime | None,
    datetime | None,
]:
    if type(snapshot) is not ResponseRetentionSnapshot:
        raise LifecycleTransitionDenied()
    if (
        type(snapshot.report_id) is not UUID
        or type(snapshot.response_id) is not UUID
        or type(snapshot.report_state) is not ReportState
        or snapshot.report_state is not ReportState.RESPONSE_AVAILABLE
        or type(snapshot.state_version) is not int
        or snapshot.state_version < 0
        or snapshot.state_version >= MAX_STATE_VERSION
    ):
        raise LifecycleTransitionDenied()

    available_at = _require_timestamp(snapshot.response_available_at)
    unread_expires_at = _require_timestamp(snapshot.unread_expires_at)
    expected_unread_expiry = _elapsed_deadline(
        available_at,
        limit=UNREAD_RESPONSE_LIMIT,
    )
    if unread_expires_at != expected_unread_expiry:
        raise LifecycleTransitionDenied()

    if snapshot.first_read_at is None:
        if snapshot.response_expires_at is not None:
            raise LifecycleTransitionDenied()
        first_read_at = None
        response_expires_at = None
    else:
        first_read_at = _require_timestamp(snapshot.first_read_at)
        response_expires_at = _require_timestamp(snapshot.response_expires_at)
        if (
            first_read_at < available_at
            or first_read_at >= unread_expires_at
            or response_expires_at
            != _elapsed_deadline(first_read_at, limit=READ_RESPONSE_LIMIT)
        ):
            raise LifecycleTransitionDenied()

    return (
        snapshot,
        available_at,
        unread_expires_at,
        first_read_at,
        response_expires_at,
    )


def plan_inert_response_retention(
    *,
    snapshot: ResponseRetentionSnapshot,
) -> InertResponseRetentionPlan:
    """Describe the exact current retention edge using trusted server time."""

    (
        validated,
        available_at,
        unread_expires_at,
        first_read_at,
        response_expires_at,
    ) = _require_snapshot(snapshot)
    observed_at = timezone.now()
    if type(observed_at) is not datetime or not timezone.is_aware(observed_at):
        raise LifecycleTransitionDenied()
    if available_at > observed_at:
        raise LifecycleTransitionDenied()

    if first_read_at is None:
        if observed_at >= unread_expires_at:
            disposition = ResponseRetentionDisposition.UNREAD_EXPIRY_DUE
        else:
            disposition = ResponseRetentionDisposition.UNREAD_WINDOW_OPEN
    else:
        if first_read_at > observed_at:
            raise LifecycleTransitionDenied()
        if observed_at >= response_expires_at:
            disposition = ResponseRetentionDisposition.READ_EXPIRY_DUE
        else:
            disposition = ResponseRetentionDisposition.READ_WINDOW_OPEN

    return InertResponseRetentionPlan(
        report_id=validated.report_id,
        response_id=validated.response_id,
        report_state=validated.report_state,
        state_version=validated.state_version,
        observed_at=observed_at,
        unread_expires_at=unread_expires_at,
        first_read_at=first_read_at,
        response_expires_at=response_expires_at,
        disposition=disposition,
    )


def execute_response_retention(*, plan: InertResponseRetentionPlan) -> Never:
    """Deny persistence, decryption, and destruction until all gates close."""

    if type(plan) is not InertResponseRetentionPlan:
        raise ResponseRetentionOrchestrationUnavailable()
    raise ResponseRetentionOrchestrationUnavailable()
