"""Pure audit-retention timing plans with no expiry capability."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Never
from uuid import UUID

from django.utils import timezone

from .errors import (
    AuditRetentionOrchestrationUnavailable,
    LifecycleTransitionDenied,
)


EVENT_RETENTION_LIMIT = timedelta(hours=365 * 24)
VERIFICATION_RETENTION_LIMIT = timedelta(hours=730 * 24)


class AuditRetentionClass(StrEnum):
    EVENT_RECEIPT_OR_PROOF = "EVENT_RECEIPT_OR_PROOF"
    CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS = (
        "CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS"
    )


class AuditRetentionDisposition(StrEnum):
    RETAIN_MINIMUM_PERIOD = "RETAIN_MINIMUM_PERIOD"
    RETAIN_VERIFICATION_DEPENDENCY = "RETAIN_VERIFICATION_DEPENDENCY"
    EXPIRY_REVIEW_DUE = "EXPIRY_REVIEW_DUE"


@dataclass(frozen=True, slots=True)
class AuditRetentionSnapshot:
    retention_id: UUID
    evidence_id: UUID
    evidence_class: AuditRetentionClass
    collector_recorded_at: datetime
    verification_dependency_required: bool


@dataclass(frozen=True, slots=True)
class InertAuditRetentionPlan:
    retention_id: UUID
    evidence_id: UUID
    evidence_class: AuditRetentionClass
    collector_recorded_at: datetime
    observed_at: datetime
    earliest_expiry_review_at: datetime
    verification_dependency_required: bool
    disposition: AuditRetentionDisposition

    authorizes_expiry: ClassVar[bool] = False
    deletes_audit_evidence: ClassVar[bool] = False
    persists_retention_batch: ClassVar[bool] = False
    exposes_witness_evidence: ClassVar[bool] = False
    calls_external_service: ClassVar[bool] = False


def _require_timestamp(value: object) -> datetime:
    if type(value) is not datetime or not timezone.is_aware(value):
        raise LifecycleTransitionDenied()
    return timezone.localtime(value, timezone=UTC)


def _retention_limit(evidence_class: AuditRetentionClass) -> timedelta:
    if evidence_class is AuditRetentionClass.EVENT_RECEIPT_OR_PROOF:
        return EVENT_RETENTION_LIMIT
    if (
        evidence_class
        is AuditRetentionClass.CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS
    ):
        return VERIFICATION_RETENTION_LIMIT
    raise LifecycleTransitionDenied()


def plan_inert_audit_retention(
    *,
    snapshot: AuditRetentionSnapshot,
) -> InertAuditRetentionPlan:
    """Describe exact audit minima without expiring any evidence."""

    if type(snapshot) is not AuditRetentionSnapshot:
        raise LifecycleTransitionDenied()
    if (
        type(snapshot.retention_id) is not UUID
        or type(snapshot.evidence_id) is not UUID
        or type(snapshot.evidence_class) is not AuditRetentionClass
        or type(snapshot.verification_dependency_required) is not bool
    ):
        raise LifecycleTransitionDenied()

    collector_recorded_at = _require_timestamp(snapshot.collector_recorded_at)
    observed_at = _require_timestamp(timezone.now())
    if collector_recorded_at > observed_at:
        raise LifecycleTransitionDenied()

    earliest_expiry_review_at = collector_recorded_at + _retention_limit(
        snapshot.evidence_class
    )
    if observed_at < earliest_expiry_review_at:
        disposition = AuditRetentionDisposition.RETAIN_MINIMUM_PERIOD
    elif snapshot.verification_dependency_required:
        disposition = (
            AuditRetentionDisposition.RETAIN_VERIFICATION_DEPENDENCY
        )
    else:
        disposition = AuditRetentionDisposition.EXPIRY_REVIEW_DUE

    return InertAuditRetentionPlan(
        retention_id=snapshot.retention_id,
        evidence_id=snapshot.evidence_id,
        evidence_class=snapshot.evidence_class,
        collector_recorded_at=collector_recorded_at,
        observed_at=observed_at,
        earliest_expiry_review_at=earliest_expiry_review_at,
        verification_dependency_required=(
            snapshot.verification_dependency_required
        ),
        disposition=disposition,
    )


def execute_audit_retention(*, plan: InertAuditRetentionPlan) -> Never:
    """Deny audit expiry and retention evidence writes until gates close."""

    if type(plan) is not InertAuditRetentionPlan:
        raise AuditRetentionOrchestrationUnavailable()
    raise AuditRetentionOrchestrationUnavailable()
