"""Boundary and denial tests for inert Response Note retention planning."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase

from report_lifecycle.errors import (
    LifecycleTransitionDenied,
    ResponseRetentionOrchestrationUnavailable,
)
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.retention import (
    READ_RESPONSE_LIMIT,
    UNREAD_RESPONSE_LIMIT,
    InertResponseRetentionPlan,
    ResponseRetentionDisposition,
    ResponseRetentionSnapshot,
    execute_response_retention,
    plan_inert_response_retention,
)
from report_lifecycle.states import ReportState
from report_lifecycle.transitions import MAX_STATE_VERSION


class InertResponseRetentionTests(TestCase):
    def setUp(self) -> None:
        self.available_at = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
        self.unread_expires_at = self.available_at + timedelta(hours=90 * 24)
        self.snapshot = ResponseRetentionSnapshot(
            report_id=uuid4(),
            response_id=uuid4(),
            report_state=ReportState.RESPONSE_AVAILABLE,
            state_version=8,
            response_available_at=self.available_at,
            unread_expires_at=self.unread_expires_at,
            first_read_at=None,
            response_expires_at=None,
        )

    def plan_at(
        self,
        observed_at: datetime,
        snapshot: ResponseRetentionSnapshot | None = None,
    ) -> InertResponseRetentionPlan:
        with patch(
            "report_lifecycle.retention.timezone.now",
            return_value=observed_at,
        ):
            return plan_inert_response_retention(
                snapshot=self.snapshot if snapshot is None else snapshot,
            )

    def test_limits_and_disposition_registry_are_exact(self) -> None:
        self.assertEqual(UNREAD_RESPONSE_LIMIT, timedelta(hours=90 * 24))
        self.assertEqual(READ_RESPONSE_LIMIT, timedelta(hours=72))
        self.assertEqual(
            tuple(ResponseRetentionDisposition),
            (
                ResponseRetentionDisposition.UNREAD_WINDOW_OPEN,
                ResponseRetentionDisposition.READ_WINDOW_OPEN,
                ResponseRetentionDisposition.UNREAD_EXPIRY_DUE,
                ResponseRetentionDisposition.READ_EXPIRY_DUE,
            ),
        )

    def test_pre_deadline_unread_window_does_not_propose_a_first_read(self) -> None:
        observed_at = self.unread_expires_at - timedelta(microseconds=1)
        plan = self.plan_at(observed_at)
        self.assertEqual(
            plan.disposition,
            ResponseRetentionDisposition.UNREAD_WINDOW_OPEN,
        )
        self.assertIsNone(plan.first_read_at)
        self.assertIsNone(plan.response_expires_at)

    def test_unread_expiry_wins_at_the_exact_boundary(self) -> None:
        plan = self.plan_at(self.unread_expires_at)
        self.assertEqual(
            plan.disposition,
            ResponseRetentionDisposition.UNREAD_EXPIRY_DUE,
        )
        self.assertIsNone(plan.first_read_at)
        self.assertIsNone(plan.response_expires_at)

    def test_existing_read_window_is_reused_without_sliding(self) -> None:
        first_read_at = self.unread_expires_at - timedelta(minutes=1)
        response_expires_at = first_read_at + timedelta(hours=72)
        snapshot = replace(
            self.snapshot,
            first_read_at=first_read_at,
            response_expires_at=response_expires_at,
        )
        plan = self.plan_at(self.unread_expires_at + timedelta(hours=1), snapshot)
        self.assertEqual(
            plan.disposition,
            ResponseRetentionDisposition.READ_WINDOW_OPEN,
        )
        self.assertEqual(plan.first_read_at, first_read_at)
        self.assertEqual(plan.response_expires_at, response_expires_at)
        self.assertGreater(plan.response_expires_at, self.unread_expires_at)

    def test_read_expiry_wins_at_the_exact_boundary(self) -> None:
        first_read_at = self.available_at + timedelta(days=1)
        response_expires_at = first_read_at + timedelta(hours=72)
        snapshot = replace(
            self.snapshot,
            first_read_at=first_read_at,
            response_expires_at=response_expires_at,
        )
        plan = self.plan_at(response_expires_at, snapshot)
        self.assertEqual(
            plan.disposition,
            ResponseRetentionDisposition.READ_EXPIRY_DUE,
        )
        self.assertEqual(plan.response_expires_at, response_expires_at)

    def test_snapshot_shape_and_deadlines_fail_closed(self) -> None:
        first_read_at = self.available_at + timedelta(days=1)
        invalid_snapshots = (
            object(),
            replace(self.snapshot, report_id="public-ticket"),
            replace(self.snapshot, response_id="response"),
            replace(self.snapshot, report_state=ReportState.OPEN),
            replace(self.snapshot, state_version=True),
            replace(self.snapshot, state_version=MAX_STATE_VERSION),
            replace(self.snapshot, response_available_at=datetime(2026, 1, 1)),
            replace(
                self.snapshot,
                unread_expires_at=self.unread_expires_at + timedelta(seconds=1),
            ),
            replace(self.snapshot, response_expires_at=self.unread_expires_at),
            replace(
                self.snapshot,
                first_read_at=self.unread_expires_at,
                response_expires_at=self.unread_expires_at + timedelta(hours=72),
            ),
            replace(
                self.snapshot,
                first_read_at=first_read_at,
                response_expires_at=first_read_at + timedelta(hours=71),
            ),
        )
        for snapshot in invalid_snapshots:
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(self.available_at + timedelta(days=2), snapshot)

    def test_future_or_untrusted_server_time_fails_closed(self) -> None:
        values = (
            self.available_at - timedelta(microseconds=1),
            datetime(2026, 1, 2),
            "browser-time",
        )
        for observed_at in values:
            with self.subTest(observed_at=observed_at):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(observed_at)

        future_first_read = self.available_at + timedelta(days=2)
        future_snapshot = replace(
            self.snapshot,
            first_read_at=future_first_read,
            response_expires_at=future_first_read + timedelta(hours=72),
        )
        with self.assertRaises(LifecycleTransitionDenied):
            self.plan_at(self.available_at + timedelta(days=1), future_snapshot)

    def test_plan_is_content_free_immutable_and_non_authorizing(self) -> None:
        plan = self.plan_at(self.available_at + timedelta(days=1))
        self.assertEqual(
            {field.name for field in fields(plan)},
            {
                "report_id",
                "response_id",
                "report_state",
                "state_version",
                "observed_at",
                "unread_expires_at",
                "first_read_at",
                "response_expires_at",
                "disposition",
            },
        )
        self.assertFalse(plan.authorizes_recovery)
        self.assertFalse(plan.persists_deadline)
        self.assertFalse(plan.decrypts_response)
        self.assertFalse(plan.destroys_key_or_content)
        with self.assertRaises(FrozenInstanceError):
            plan.state_version = 9

    def test_executor_always_fails_closed_without_database_writes(self) -> None:
        plan = self.plan_at(self.available_at + timedelta(days=1))
        for value in (plan, object()):
            with self.subTest(value=value):
                with self.assertRaises(
                    ResponseRetentionOrchestrationUnavailable
                ) as raised:
                    execute_response_retention(plan=value)
                self.assertEqual(
                    str(raised.exception),
                    "response_retention_orchestration_unavailable",
                )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_controlled_errors_do_not_echo_untrusted_values(self) -> None:
        sentinel = "RECOVERY_SECRET_SENTINEL"
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            self.plan_at(
                self.available_at + timedelta(days=1),
                replace(self.snapshot, response_id=sentinel),
            )
        self.assertNotIn(sentinel, repr(raised.exception))
