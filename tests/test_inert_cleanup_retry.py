"""Exact timing and denial tests for inert ciphertext-cleanup planning."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase

from report_lifecycle.cleanup import (
    FIRST_DAY_BOUNDARY,
    FIRST_DAY_RETRY_DELAY,
    FIRST_HOUR_BOUNDARY,
    FIRST_HOUR_RETRY_DELAY,
    FIRST_RETRY_DELAY,
    LONG_TERM_RETRY_DELAY,
    MAXIMUM_JITTER_FRACTION,
    MAXIMUM_RECONCILER_INTERVAL,
    PERSISTENT_FAILURE_ALERT_DELAY,
    SECOND_RETRY_DELAY,
    THIRD_RETRY_DELAY,
    CleanupAlertDisposition,
    CleanupFailureSnapshot,
    CleanupRetryTier,
    InertCleanupRetryPlan,
    execute_cleanup_retry,
    plan_inert_cleanup_retry,
)
from report_lifecycle.errors import (
    CleanupOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.transitions import MAX_STATE_VERSION


class InertCleanupRetryTests(TestCase):
    def setUp(self) -> None:
        self.first_failed_at = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
        self.snapshot = CleanupFailureSnapshot(
            cleanup_id=uuid4(),
            idempotency_id=uuid4(),
            failure_count=1,
            first_failed_at=self.first_failed_at,
            last_failed_at=self.first_failed_at,
            persistent_alert_recorded_at=None,
        )

    def plan_at(
        self,
        observed_at: datetime,
        snapshot: CleanupFailureSnapshot | None = None,
    ) -> InertCleanupRetryPlan:
        with patch(
            "report_lifecycle.cleanup.timezone.now",
            return_value=observed_at,
        ):
            return plan_inert_cleanup_retry(
                snapshot=self.snapshot if snapshot is None else snapshot,
            )

    def test_fixed_schedule_constants_are_exact(self) -> None:
        self.assertEqual(FIRST_RETRY_DELAY, timedelta(seconds=5))
        self.assertEqual(SECOND_RETRY_DELAY, timedelta(seconds=30))
        self.assertEqual(THIRD_RETRY_DELAY, timedelta(minutes=2))
        self.assertEqual(FIRST_HOUR_RETRY_DELAY, timedelta(minutes=5))
        self.assertEqual(FIRST_DAY_RETRY_DELAY, timedelta(hours=1))
        self.assertEqual(LONG_TERM_RETRY_DELAY, timedelta(hours=6))
        self.assertEqual(FIRST_HOUR_BOUNDARY, timedelta(hours=1))
        self.assertEqual(FIRST_DAY_BOUNDARY, timedelta(hours=24))
        self.assertEqual(PERSISTENT_FAILURE_ALERT_DELAY, timedelta(minutes=15))
        self.assertEqual(MAXIMUM_RECONCILER_INTERVAL, timedelta(minutes=1))
        self.assertEqual(MAXIMUM_JITTER_FRACTION, (1, 10))
        self.assertEqual(
            tuple(CleanupRetryTier),
            (
                CleanupRetryTier.FIRST_FIVE_SECONDS,
                CleanupRetryTier.SECOND_THIRTY_SECONDS,
                CleanupRetryTier.THIRD_TWO_MINUTES,
                CleanupRetryTier.FIVE_MINUTES_FIRST_HOUR,
                CleanupRetryTier.HOURLY_THROUGH_FIRST_DAY,
                CleanupRetryTier.SIX_HOURLY_INDEFINITE,
            ),
        )
        self.assertEqual(
            tuple(CleanupAlertDisposition),
            (
                CleanupAlertDisposition.NOT_DUE,
                CleanupAlertDisposition.SUBMISSION_DUE,
                CleanupAlertDisposition.RECORDED,
            ),
        )

    def test_first_three_failures_use_the_exact_initial_delays(self) -> None:
        cases = (
            (1, CleanupRetryTier.FIRST_FIVE_SECONDS, timedelta(seconds=5)),
            (2, CleanupRetryTier.SECOND_THIRTY_SECONDS, timedelta(seconds=30)),
            (3, CleanupRetryTier.THIRD_TWO_MINUTES, timedelta(minutes=2)),
        )
        for count, tier, delay in cases:
            snapshot = replace(self.snapshot, failure_count=count)
            with self.subTest(count=count):
                plan = self.plan_at(self.first_failed_at, snapshot)
                self.assertEqual(plan.retry_tier, tier)
                self.assertEqual(plan.base_retry_delay, delay)
                self.assertEqual(plan.maximum_jitter, delay / 10)
                self.assertEqual(
                    plan.next_base_retry_at,
                    self.first_failed_at + delay,
                )

    def test_later_tiers_change_at_exact_elapsed_boundaries(self) -> None:
        cases = (
            (
                FIRST_HOUR_BOUNDARY - timedelta(microseconds=1),
                CleanupRetryTier.FIVE_MINUTES_FIRST_HOUR,
                timedelta(minutes=5),
            ),
            (
                FIRST_HOUR_BOUNDARY,
                CleanupRetryTier.HOURLY_THROUGH_FIRST_DAY,
                timedelta(hours=1),
            ),
            (
                FIRST_DAY_BOUNDARY - timedelta(microseconds=1),
                CleanupRetryTier.HOURLY_THROUGH_FIRST_DAY,
                timedelta(hours=1),
            ),
            (
                FIRST_DAY_BOUNDARY,
                CleanupRetryTier.SIX_HOURLY_INDEFINITE,
                timedelta(hours=6),
            ),
            (
                timedelta(days=3650),
                CleanupRetryTier.SIX_HOURLY_INDEFINITE,
                timedelta(hours=6),
            ),
        )
        for elapsed, tier, delay in cases:
            failed_at = self.first_failed_at + elapsed
            snapshot = replace(
                self.snapshot,
                failure_count=MAX_STATE_VERSION - 1,
                last_failed_at=failed_at,
            )
            with self.subTest(elapsed=elapsed):
                plan = self.plan_at(failed_at, snapshot)
                self.assertEqual(plan.retry_tier, tier)
                self.assertEqual(plan.base_retry_delay, delay)

    def test_alert_is_due_once_at_the_exact_15_minute_boundary(self) -> None:
        before = self.plan_at(
            self.first_failed_at
            + PERSISTENT_FAILURE_ALERT_DELAY
            - timedelta(microseconds=1)
        )
        self.assertEqual(before.alert_disposition, CleanupAlertDisposition.NOT_DUE)

        boundary = self.plan_at(
            self.first_failed_at + PERSISTENT_FAILURE_ALERT_DELAY
        )
        self.assertEqual(
            boundary.alert_disposition,
            CleanupAlertDisposition.SUBMISSION_DUE,
        )

        recorded_at = self.first_failed_at + PERSISTENT_FAILURE_ALERT_DELAY
        recorded_snapshot = replace(
            self.snapshot,
            persistent_alert_recorded_at=recorded_at,
        )
        recorded = self.plan_at(recorded_at, recorded_snapshot)
        self.assertEqual(
            recorded.alert_disposition,
            CleanupAlertDisposition.RECORDED,
        )

    def test_invalid_identifiers_counters_and_times_fail_closed(self) -> None:
        invalid = (
            object(),
            replace(self.snapshot, cleanup_id="object/path"),
            replace(self.snapshot, idempotency_id="retry"),
            replace(self.snapshot, failure_count=True),
            replace(self.snapshot, failure_count=0),
            replace(self.snapshot, failure_count=MAX_STATE_VERSION),
            replace(self.snapshot, first_failed_at=datetime(2026, 1, 1)),
            replace(
                self.snapshot,
                last_failed_at=self.first_failed_at - timedelta(seconds=1),
            ),
            replace(
                self.snapshot,
                persistent_alert_recorded_at=(
                    self.first_failed_at + timedelta(minutes=14)
                ),
            ),
        )
        observed_at = self.first_failed_at + timedelta(hours=1)
        for snapshot in invalid:
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(observed_at, snapshot)

    def test_future_or_untrusted_server_time_fails_closed(self) -> None:
        for observed_at in (
            self.first_failed_at - timedelta(microseconds=1),
            datetime(2026, 1, 1),
            "browser-time",
        ):
            with self.subTest(observed_at=observed_at):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan_at(observed_at)

    def test_plan_is_content_free_immutable_and_non_authorizing(self) -> None:
        plan = self.plan_at(self.first_failed_at)
        self.assertEqual(
            {field.name for field in fields(plan)},
            {
                "cleanup_id",
                "idempotency_id",
                "failure_count",
                "first_failed_at",
                "last_failed_at",
                "observed_at",
                "retry_tier",
                "base_retry_delay",
                "maximum_jitter",
                "next_base_retry_at",
                "persistent_alert_due_at",
                "alert_disposition",
            },
        )
        self.assertFalse(plan.authorizes_deletion)
        self.assertFalse(plan.schedules_task)
        self.assertFalse(plan.persists_state)
        self.assertFalse(plan.submits_alert)
        self.assertFalse(plan.calls_external_service)
        with self.assertRaises(FrozenInstanceError):
            plan.failure_count = 2

    def test_executor_always_fails_closed_without_database_writes(self) -> None:
        plan = self.plan_at(self.first_failed_at)
        for value in (plan, object()):
            with self.subTest(value=value):
                with self.assertRaises(CleanupOrchestrationUnavailable) as raised:
                    execute_cleanup_retry(plan=value)
                self.assertEqual(
                    str(raised.exception),
                    "cleanup_orchestration_unavailable",
                )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_controlled_errors_do_not_echo_untrusted_values(self) -> None:
        sentinel = "PROVIDER_ERROR_OR_FILENAME_SENTINEL"
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            self.plan_at(
                self.first_failed_at,
                replace(self.snapshot, cleanup_id=sentinel),
            )
        self.assertNotIn(sentinel, repr(raised.exception))
