"""Boundary and denial tests for isolated audit-retention planning."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase

from report_lifecycle.audit_retention import (
    EVENT_RETENTION_LIMIT,
    VERIFICATION_RETENTION_LIMIT,
    AuditRetentionClass,
    AuditRetentionDisposition,
    AuditRetentionSnapshot,
    InertAuditRetentionPlan,
    execute_audit_retention,
    plan_inert_audit_retention,
)
from report_lifecycle.errors import (
    AuditRetentionOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from report_lifecycle.models import Report, ReportLease, SecurityOperation


class InertAuditRetentionTests(TestCase):
    def setUp(self) -> None:
        self.collector_recorded_at = datetime(
            2026, 1, 1, 10, 0, tzinfo=UTC
        )
        self.snapshot = AuditRetentionSnapshot(
            retention_id=uuid4(),
            evidence_id=uuid4(),
            evidence_class=AuditRetentionClass.EVENT_RECEIPT_OR_PROOF,
            collector_recorded_at=self.collector_recorded_at,
            verification_dependency_required=False,
        )

    def plan_at(
        self,
        observed_at: datetime,
        snapshot: AuditRetentionSnapshot | None = None,
    ) -> InertAuditRetentionPlan:
        with patch(
            "report_lifecycle.audit_retention.timezone.now",
            return_value=observed_at,
        ):
            return plan_inert_audit_retention(
                snapshot=self.snapshot if snapshot is None else snapshot,
            )

    def test_limits_and_closed_registries_are_exact(self) -> None:
        self.assertEqual(EVENT_RETENTION_LIMIT, timedelta(hours=365 * 24))
        self.assertEqual(
            VERIFICATION_RETENTION_LIMIT,
            timedelta(hours=730 * 24),
        )
        self.assertEqual(
            tuple(AuditRetentionClass),
            (
                AuditRetentionClass.EVENT_RECEIPT_OR_PROOF,
                AuditRetentionClass.CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS,
            ),
        )
        self.assertEqual(
            tuple(AuditRetentionDisposition),
            (
                AuditRetentionDisposition.RETAIN_MINIMUM_PERIOD,
                AuditRetentionDisposition.RETAIN_VERIFICATION_DEPENDENCY,
                AuditRetentionDisposition.EXPIRY_REVIEW_DUE,
            ),
        )

    def test_event_evidence_is_retained_before_365_day_boundary(self) -> None:
        boundary = self.collector_recorded_at + EVENT_RETENTION_LIMIT
        plan = self.plan_at(boundary - timedelta(microseconds=1))
        self.assertEqual(
            plan.disposition,
            AuditRetentionDisposition.RETAIN_MINIMUM_PERIOD,
        )
        self.assertEqual(plan.earliest_expiry_review_at, boundary)

    def test_event_boundary_marks_only_expiry_review_due(self) -> None:
        boundary = self.collector_recorded_at + EVENT_RETENTION_LIMIT
        plan = self.plan_at(boundary)
        self.assertEqual(
            plan.disposition,
            AuditRetentionDisposition.EXPIRY_REVIEW_DUE,
        )
        self.assertFalse(plan.authorizes_expiry)

    def test_verification_evidence_uses_the_730_day_boundary(self) -> None:
        snapshot = replace(
            self.snapshot,
            evidence_class=(
                AuditRetentionClass.CHECKPOINT_CONSISTENCY_KEY_OR_WITNESS
            ),
        )
        boundary = self.collector_recorded_at + VERIFICATION_RETENTION_LIMIT
        before = self.plan_at(boundary - timedelta(microseconds=1), snapshot)
        due = self.plan_at(boundary, snapshot)
        self.assertEqual(
            before.disposition,
            AuditRetentionDisposition.RETAIN_MINIMUM_PERIOD,
        )
        self.assertEqual(
            due.disposition,
            AuditRetentionDisposition.EXPIRY_REVIEW_DUE,
        )

    def test_required_dependency_retains_after_the_minimum_period(self) -> None:
        snapshot = replace(
            self.snapshot,
            verification_dependency_required=True,
        )
        plan = self.plan_at(
            self.collector_recorded_at + EVENT_RETENTION_LIMIT,
            snapshot,
        )
        self.assertEqual(
            plan.disposition,
            AuditRetentionDisposition.RETAIN_VERIFICATION_DEPENDENCY,
        )
        self.assertFalse(plan.authorizes_expiry)

    def test_elapsed_period_is_computed_in_utc_across_offsets(self) -> None:
        collector_recorded_at = datetime.fromisoformat(
            "2026-03-28T23:30:00+01:00"
        )
        boundary = (
            collector_recorded_at.astimezone(UTC) + EVENT_RETENTION_LIMIT
        )
        snapshot = replace(
            self.snapshot,
            collector_recorded_at=collector_recorded_at,
        )
        plan = self.plan_at(boundary, snapshot)
        self.assertEqual(
            plan.disposition,
            AuditRetentionDisposition.EXPIRY_REVIEW_DUE,
        )
        self.assertEqual(plan.earliest_expiry_review_at, boundary)

    def test_invalid_identifiers_class_dependency_and_times_fail_closed(self) -> None:
        invalid = (
            object(),
            replace(self.snapshot, retention_id="retention"),
            replace(self.snapshot, evidence_id="event"),
            replace(self.snapshot, evidence_class="EVENT"),
            replace(self.snapshot, verification_dependency_required=1),
            replace(
                self.snapshot,
                collector_recorded_at=datetime(2026, 1, 1, 10, 0),
            ),
            replace(
                self.snapshot,
                collector_recorded_at=(
                    self.collector_recorded_at + timedelta(seconds=1)
                ),
            ),
        )
        for snapshot in invalid:
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(self.collector_recorded_at, snapshot)

    def test_untrusted_collector_observation_time_fails_closed(self) -> None:
        for observed_at in (datetime(2026, 1, 1, 10, 0), "client-time"):
            with self.subTest(observed_at=observed_at):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(observed_at)

    def test_plan_is_content_free_immutable_and_non_authorizing(self) -> None:
        plan = self.plan_at(self.collector_recorded_at)
        self.assertEqual(
            {field.name for field in fields(plan)},
            {
                "retention_id",
                "evidence_id",
                "evidence_class",
                "collector_recorded_at",
                "observed_at",
                "earliest_expiry_review_at",
                "verification_dependency_required",
                "disposition",
            },
        )
        self.assertFalse(plan.authorizes_expiry)
        self.assertFalse(plan.deletes_audit_evidence)
        self.assertFalse(plan.persists_retention_batch)
        self.assertFalse(plan.exposes_witness_evidence)
        self.assertFalse(plan.calls_external_service)
        with self.assertRaises(FrozenInstanceError):
            plan.evidence_id = uuid4()

    def test_executor_always_fails_closed_without_database_writes(self) -> None:
        plan = self.plan_at(self.collector_recorded_at)
        for value in (plan, object()):
            with self.subTest(value=value):
                with self.assertRaises(
                    AuditRetentionOrchestrationUnavailable
                ) as raised:
                    execute_audit_retention(plan=value)
                self.assertEqual(
                    str(raised.exception),
                    "audit_retention_orchestration_unavailable",
                )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_controlled_errors_do_not_echo_untrusted_values(self) -> None:
        sentinel = "REPORT_TEXT_OR_RECOVERY_SECRET_SENTINEL"
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            self.plan_at(
                self.collector_recorded_at,
                replace(self.snapshot, evidence_id=sentinel),
            )
        self.assertNotIn(sentinel, repr(raised.exception))
