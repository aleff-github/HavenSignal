"""Boundary and denial tests for terminal application metadata retention."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase

from report_lifecycle.errors import (
    LifecycleTransitionDenied,
    MetadataRetentionOrchestrationUnavailable,
)
from report_lifecycle.metadata_retention import (
    TERMINAL_METADATA_RETENTION_LIMIT,
    InertTerminalMetadataRetentionPlan,
    TerminalMetadataRetentionDisposition,
    TerminalMetadataRetentionSnapshot,
    execute_terminal_metadata_retention,
    plan_inert_terminal_metadata_retention,
)
from report_lifecycle.models import Report, ReportLease, SecurityOperation


class InertTerminalMetadataRetentionTests(TestCase):
    def setUp(self) -> None:
        self.confirmed_at = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
        self.snapshot = TerminalMetadataRetentionSnapshot(
            retention_id=uuid4(),
            cleanup_id=uuid4(),
            cleanup_confirmed_at=self.confirmed_at,
        )

    def plan_at(
        self,
        observed_at: datetime,
        snapshot: TerminalMetadataRetentionSnapshot | None = None,
    ) -> InertTerminalMetadataRetentionPlan:
        with patch(
            "report_lifecycle.metadata_retention.timezone.now",
            return_value=observed_at,
        ):
            return plan_inert_terminal_metadata_retention(
                snapshot=self.snapshot if snapshot is None else snapshot,
            )

    def test_limit_and_disposition_registry_are_exact(self) -> None:
        self.assertEqual(
            TERMINAL_METADATA_RETENTION_LIMIT,
            timedelta(hours=30 * 24),
        )
        self.assertEqual(
            tuple(TerminalMetadataRetentionDisposition),
            (
                TerminalMetadataRetentionDisposition.RETAIN_CLEANUP_INCOMPLETE,
                TerminalMetadataRetentionDisposition.RETAIN_MINIMUM_PERIOD,
                TerminalMetadataRetentionDisposition.REMOVAL_REVIEW_DUE,
            ),
        )

    def test_incomplete_cleanup_retains_without_a_removal_time(self) -> None:
        snapshot = replace(self.snapshot, cleanup_confirmed_at=None)
        plan = self.plan_at(self.confirmed_at, snapshot)
        self.assertEqual(
            plan.disposition,
            TerminalMetadataRetentionDisposition.RETAIN_CLEANUP_INCOMPLETE,
        )
        self.assertIsNone(plan.cleanup_confirmed_at)
        self.assertIsNone(plan.earliest_removal_at)

    def test_minimum_period_is_exactly_thirty_times_twenty_four_hours(self) -> None:
        boundary = self.confirmed_at + timedelta(hours=30 * 24)
        plan = self.plan_at(boundary - timedelta(microseconds=1))
        self.assertEqual(
            plan.disposition,
            TerminalMetadataRetentionDisposition.RETAIN_MINIMUM_PERIOD,
        )
        self.assertEqual(plan.earliest_removal_at, boundary)

    def test_exact_boundary_only_marks_removal_review_due(self) -> None:
        boundary = self.confirmed_at + timedelta(hours=30 * 24)
        plan = self.plan_at(boundary)
        self.assertEqual(
            plan.disposition,
            TerminalMetadataRetentionDisposition.REMOVAL_REVIEW_DUE,
        )
        self.assertEqual(plan.earliest_removal_at, boundary)
        self.assertFalse(plan.authorizes_removal)

    def test_elapsed_period_is_computed_in_utc_across_offsets(self) -> None:
        confirmed_at = datetime.fromisoformat("2026-03-28T23:30:00+01:00")
        boundary = datetime.fromisoformat("2026-04-28T00:30:00+02:00")
        snapshot = replace(
            self.snapshot,
            cleanup_confirmed_at=confirmed_at,
        )
        plan = self.plan_at(boundary, snapshot)
        self.assertEqual(
            plan.disposition,
            TerminalMetadataRetentionDisposition.REMOVAL_REVIEW_DUE,
        )
        self.assertEqual(
            plan.earliest_removal_at,
            datetime(2026, 4, 27, 22, 30, tzinfo=UTC),
        )

    def test_invalid_identifiers_and_confirmation_times_fail_closed(self) -> None:
        invalid = (
            object(),
            replace(self.snapshot, retention_id="ticket-id"),
            replace(self.snapshot, cleanup_id="object/path"),
            replace(
                self.snapshot,
                cleanup_confirmed_at=datetime(2026, 1, 1, 10, 0),
            ),
            replace(
                self.snapshot,
                cleanup_confirmed_at=self.confirmed_at + timedelta(seconds=1),
            ),
        )
        for snapshot in invalid:
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(self.confirmed_at, snapshot)

    def test_untrusted_server_time_fails_closed_even_if_cleanup_is_incomplete(self) -> None:
        snapshot = replace(self.snapshot, cleanup_confirmed_at=None)
        for observed_at in (datetime(2026, 1, 1, 10, 0), "client-time"):
            with self.subTest(observed_at=observed_at):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(observed_at, snapshot)

    def test_plan_is_content_free_immutable_and_non_authorizing(self) -> None:
        plan = self.plan_at(self.confirmed_at)
        self.assertEqual(
            {field.name for field in fields(plan)},
            {
                "retention_id",
                "cleanup_id",
                "observed_at",
                "cleanup_confirmed_at",
                "earliest_removal_at",
                "disposition",
            },
        )
        self.assertFalse(plan.authorizes_removal)
        self.assertFalse(plan.deletes_ticket_lookup)
        self.assertFalse(plan.persists_state)
        self.assertFalse(plan.schedules_job)
        self.assertFalse(plan.calls_external_service)
        with self.assertRaises(FrozenInstanceError):
            plan.cleanup_id = uuid4()

    def test_executor_always_fails_closed_without_database_writes(self) -> None:
        plan = self.plan_at(self.confirmed_at)
        for value in (plan, object()):
            with self.subTest(value=value):
                with self.assertRaises(
                    MetadataRetentionOrchestrationUnavailable
                ) as raised:
                    execute_terminal_metadata_retention(plan=value)
                self.assertEqual(
                    str(raised.exception),
                    "metadata_retention_orchestration_unavailable",
                )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_controlled_errors_do_not_echo_untrusted_values(self) -> None:
        sentinel = "RECOVERY_SECRET_OR_FILENAME_SENTINEL"
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            self.plan_at(
                self.confirmed_at,
                replace(self.snapshot, retention_id=sentinel),
            )
        self.assertNotIn(sentinel, repr(raised.exception))
