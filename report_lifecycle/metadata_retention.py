"""Pure terminal-metadata retention planning with no removal capability."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Never
from uuid import UUID

from django.utils import timezone

from .errors import (
    LifecycleTransitionDenied,
    MetadataRetentionOrchestrationUnavailable,
)


TERMINAL_METADATA_RETENTION_LIMIT = timedelta(hours=30 * 24)


class TerminalMetadataRetentionDisposition(StrEnum):
    RETAIN_CLEANUP_INCOMPLETE = "RETAIN_CLEANUP_INCOMPLETE"
    RETAIN_MINIMUM_PERIOD = "RETAIN_MINIMUM_PERIOD"
    REMOVAL_REVIEW_DUE = "REMOVAL_REVIEW_DUE"


@dataclass(frozen=True, slots=True)
class TerminalMetadataRetentionSnapshot:
    retention_id: UUID
    cleanup_id: UUID
    cleanup_confirmed_at: datetime | None


@dataclass(frozen=True, slots=True)
class InertTerminalMetadataRetentionPlan:
    retention_id: UUID
    cleanup_id: UUID
    observed_at: datetime
    cleanup_confirmed_at: datetime | None
    earliest_removal_at: datetime | None
    disposition: TerminalMetadataRetentionDisposition

    authorizes_removal: ClassVar[bool] = False
    deletes_ticket_lookup: ClassVar[bool] = False
    persists_state: ClassVar[bool] = False
    schedules_job: ClassVar[bool] = False
    calls_external_service: ClassVar[bool] = False


def _require_timestamp(value: object) -> datetime:
    if type(value) is not datetime or not timezone.is_aware(value):
        raise LifecycleTransitionDenied()
    return timezone.localtime(value, timezone=UTC)


def plan_inert_terminal_metadata_retention(
    *,
    snapshot: TerminalMetadataRetentionSnapshot,
) -> InertTerminalMetadataRetentionPlan:
    """Describe the minimum retention boundary without removing metadata."""

    if type(snapshot) is not TerminalMetadataRetentionSnapshot:
        raise LifecycleTransitionDenied()
    if (
        type(snapshot.retention_id) is not UUID
        or type(snapshot.cleanup_id) is not UUID
    ):
        raise LifecycleTransitionDenied()

    observed_at = _require_timestamp(timezone.now())
    if snapshot.cleanup_confirmed_at is None:
        cleanup_confirmed_at = None
        earliest_removal_at = None
        disposition = (
            TerminalMetadataRetentionDisposition.RETAIN_CLEANUP_INCOMPLETE
        )
    else:
        cleanup_confirmed_at = _require_timestamp(
            snapshot.cleanup_confirmed_at
        )
        if cleanup_confirmed_at > observed_at:
            raise LifecycleTransitionDenied()
        earliest_removal_at = (
            cleanup_confirmed_at + TERMINAL_METADATA_RETENTION_LIMIT
        )
        if observed_at < earliest_removal_at:
            disposition = (
                TerminalMetadataRetentionDisposition.RETAIN_MINIMUM_PERIOD
            )
        else:
            disposition = (
                TerminalMetadataRetentionDisposition.REMOVAL_REVIEW_DUE
            )

    return InertTerminalMetadataRetentionPlan(
        retention_id=snapshot.retention_id,
        cleanup_id=snapshot.cleanup_id,
        observed_at=observed_at,
        cleanup_confirmed_at=cleanup_confirmed_at,
        earliest_removal_at=earliest_removal_at,
        disposition=disposition,
    )


def execute_terminal_metadata_retention(
    *,
    plan: InertTerminalMetadataRetentionPlan,
) -> Never:
    """Deny retention jobs and metadata removal until all gates close."""

    if type(plan) is not InertTerminalMetadataRetentionPlan:
        raise MetadataRetentionOrchestrationUnavailable()
    raise MetadataRetentionOrchestrationUnavailable()
