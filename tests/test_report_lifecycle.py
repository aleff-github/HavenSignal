"""Stage A lifecycle policy, metadata, and abuse-case tests."""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from anonymous_reporting import urls
from report_lifecycle.errors import LifecycleTransitionDenied
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.states import (
    LEASE_TRANSITIONS,
    REPORT_TRANSITIONS,
    SECURITY_OPERATION_TRANSITIONS,
    LeaseState,
    ReportState,
    SecurityOperationKind,
    SecurityOperationState,
    require_lease_transition,
    require_report_transition,
    require_security_operation_transition,
)
from report_lifecycle.transitions import (
    LEASE_IDLE_LIMIT,
    MAX_STATE_VERSION,
    plan_lease_activity,
    plan_lease_transition,
    plan_next_lease_generation,
    plan_report_transition,
    plan_security_operation_transition,
)


class LifecycleTransitionPolicyTests(SimpleTestCase):
    def test_every_documented_report_edge_is_exact(self) -> None:
        expected = {
            (ReportState.SEALED, ReportState.CLAIMED),
            (ReportState.SEALED, ReportState.DELETING_FLOOD),
            (ReportState.CLAIMED, ReportState.SEALED),
            (ReportState.CLAIMED, ReportState.OPEN),
            (ReportState.OPEN, ReportState.INTERRUPTED),
            (ReportState.OPEN, ReportState.FINALIZING),
            (ReportState.OPEN, ReportState.DELETING),
            (ReportState.INTERRUPTED, ReportState.OPEN),
            (ReportState.FINALIZING, ReportState.RESPONSE_AVAILABLE),
            (ReportState.RESPONSE_AVAILABLE, ReportState.DESTROYED),
            (ReportState.DELETING, ReportState.DELETED_WITH_REASON),
            (
                ReportState.DELETING_FLOOD,
                ReportState.DELETED_UNOPENED_EMERGENCY,
            ),
        }
        actual = {
            (source, target)
            for source, targets in REPORT_TRANSITIONS.items()
            for target in targets
        }
        self.assertEqual(actual, expected)

    def test_every_other_report_edge_fails_closed(self) -> None:
        for source in ReportState:
            for target in ReportState:
                if target in REPORT_TRANSITIONS[source]:
                    continue
                with self.subTest(source=source, target=target):
                    with self.assertRaises(LifecycleTransitionDenied) as raised:
                        require_report_transition(source, target)
                    self.assertEqual(
                        str(raised.exception),
                        "lifecycle_transition_denied",
                    )

    def test_lease_and_operation_edges_are_terminal_and_exact(self) -> None:
        self.assertEqual(
            LEASE_TRANSITIONS[LeaseState.ACTIVE],
            {
                LeaseState.RELEASED,
                LeaseState.EXPIRED,
                LeaseState.INVALIDATED,
            },
        )
        for terminal in (
            LeaseState.RELEASED,
            LeaseState.EXPIRED,
            LeaseState.INVALIDATED,
        ):
            self.assertEqual(LEASE_TRANSITIONS[terminal], frozenset())

        self.assertEqual(
            SECURITY_OPERATION_TRANSITIONS[SecurityOperationState.PREPARED],
            {SecurityOperationState.ACTIVE, SecurityOperationState.ABORTED},
        )
        self.assertEqual(
            SECURITY_OPERATION_TRANSITIONS[SecurityOperationState.ACTIVE],
            {
                SecurityOperationState.COMPLETED,
                SecurityOperationState.FAILED,
                SecurityOperationState.ABORTED,
            },
        )
        for terminal in (
            SecurityOperationState.COMPLETED,
            SecurityOperationState.FAILED,
            SecurityOperationState.ABORTED,
        ):
            self.assertEqual(
                SECURITY_OPERATION_TRANSITIONS[terminal],
                frozenset(),
            )

    def test_unknown_states_share_one_controlled_denial(self) -> None:
        calls = (
            lambda: require_report_transition("UNKNOWN", ReportState.CLAIMED),
            lambda: require_lease_transition("UNKNOWN", LeaseState.EXPIRED),
            lambda: require_security_operation_transition(
                "UNKNOWN",
                SecurityOperationState.ACTIVE,
            ),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(LifecycleTransitionDenied) as raised:
                    call()
                self.assertEqual(str(raised.exception), "lifecycle_transition_denied")

    def test_planners_increment_one_version_and_use_server_time(self) -> None:
        before = timezone.now()
        report_plan = plan_report_transition(
            report_id=uuid4(),
            current_state=ReportState.SEALED,
            current_version=9,
            target_state=ReportState.CLAIMED,
        )
        lease_plan = plan_lease_transition(
            lease_id=uuid4(),
            current_state=LeaseState.ACTIVE,
            current_version=4,
            target_state=LeaseState.EXPIRED,
        )
        operation_plan = plan_security_operation_transition(
            operation_id=uuid4(),
            current_state=SecurityOperationState.PREPARED,
            current_version=0,
            target_state=SecurityOperationState.ACTIVE,
        )
        after = timezone.now()

        self.assertEqual(report_plan.target_version, 10)
        self.assertEqual(lease_plan.target_version, 5)
        self.assertEqual(operation_plan.target_version, 1)
        for changed_at in (
            report_plan.changed_at,
            lease_plan.changed_at,
            operation_plan.changed_at,
        ):
            self.assertLessEqual(before, changed_at)
            self.assertLessEqual(changed_at, after)

    def test_planners_reject_non_uuid_and_invalid_versions(self) -> None:
        for invalid_version in (-1, True, 1.5, "1", MAX_STATE_VERSION):
            with self.subTest(version=invalid_version):
                with self.assertRaises(LifecycleTransitionDenied):
                    plan_report_transition(
                        report_id=uuid4(),
                        current_state=ReportState.SEALED,
                        current_version=invalid_version,
                        target_state=ReportState.CLAIMED,
                    )

        with self.assertRaises(LifecycleTransitionDenied):
            plan_security_operation_transition(
                operation_id="browser-value",
                current_state=SecurityOperationState.PREPARED,
                current_version=0,
                target_state=SecurityOperationState.ACTIVE,
            )

    def test_next_lease_generation_is_monotonic_and_server_timed(self) -> None:
        before = timezone.now()
        plan = plan_next_lease_generation(report_id=uuid4(), current_generation=7)
        after = timezone.now()
        self.assertEqual(plan.current_generation, 7)
        self.assertEqual(plan.next_generation, 8)
        self.assertLessEqual(before, plan.changed_at)
        self.assertLessEqual(plan.changed_at, after)

        for invalid_generation in (-1, True, MAX_STATE_VERSION):
            with self.subTest(generation=invalid_generation):
                with self.assertRaises(LifecycleTransitionDenied):
                    plan_next_lease_generation(
                        report_id=uuid4(),
                        current_generation=invalid_generation,
                    )


class LeaseActivityPlannerTests(SimpleTestCase):
    def setUp(self) -> None:
        self.now = timezone.now()
        self.lease_id = uuid4()

    def plan(self, **overrides: object):
        values = {
            "lease_id": self.lease_id,
            "current_generation": 7,
            "presented_generation": 7,
            "opened_at": self.now - timedelta(minutes=20),
            "last_activity_at": self.now - timedelta(minutes=1),
            "absolute_expires_at": self.now + timedelta(minutes=40),
        }
        values.update(overrides)
        with patch("report_lifecycle.transitions.timezone.now", return_value=self.now):
            return plan_lease_activity(**values)

    def test_valid_activity_uses_server_time_without_extending_absolute_expiry(self) -> None:
        absolute_expiry = self.now + timedelta(minutes=40)
        plan = self.plan(absolute_expires_at=absolute_expiry)
        self.assertEqual(plan.next_activity_at, self.now)
        self.assertEqual(plan.absolute_expires_at, absolute_expiry)
        self.assertEqual(plan.generation, 7)

    def test_stale_generation_fails_closed(self) -> None:
        with self.assertRaises(LifecycleTransitionDenied):
            self.plan(presented_generation=6)

    def test_idle_and_absolute_boundaries_fail_closed(self) -> None:
        cases = (
            {"last_activity_at": self.now - LEASE_IDLE_LIMIT},
            {"absolute_expires_at": self.now},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan(**values)

    def test_invalid_or_future_timestamps_fail_closed(self) -> None:
        naive = self.now.replace(tzinfo=None)
        cases = (
            {"opened_at": naive},
            {"last_activity_at": self.now + timedelta(seconds=1)},
            {"absolute_expires_at": self.now - timedelta(minutes=21)},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(LifecycleTransitionDenied):
                    self.plan(**values)


class LifecycleMetadataPersistenceTests(TestCase):
    def setUp(self) -> None:
        self.report = Report.objects.create()
        self.operator_id = uuid4()
        self.now = timezone.now()

    def make_lease(
        self,
        *,
        report: Report | None = None,
        operator_id=None,
        generation: int = 1,
    ) -> ReportLease:
        return ReportLease.objects.create(
            report=report or self.report,
            operator_id=operator_id or self.operator_id,
            generation=generation,
            opened_at=self.now,
            last_activity_at=self.now,
            absolute_expires_at=self.now + timedelta(hours=1),
        )

    def test_models_contain_only_allowlisted_internal_metadata(self) -> None:
        forbidden_fragments = {
            "alert",
            "attachment",
            "audit",
            "body",
            "ciphertext",
            "content",
            "credential",
            "dek",
            "filename",
            "header",
            "ip_address",
            "key",
            "note",
            "plaintext",
            "recovery",
            "secret",
            "ticket",
            "user_agent",
            "verifier",
        }
        for model in (Report, ReportLease, SecurityOperation):
            self.assertEqual(model._meta.default_permissions, ())
            for field in model._meta.fields:
                with self.subTest(model=model.__name__, field=field.name):
                    self.assertFalse(
                        any(
                            fragment in field.name.lower()
                            for fragment in forbidden_fragments
                        )
                    )

    def test_new_report_is_only_initial_sealed_metadata(self) -> None:
        self.assertEqual(self.report.state, ReportState.SEALED)
        self.assertEqual(self.report.state_version, 0)
        self.assertEqual(self.report.current_lease_generation, 0)
        self.assertIsNone(self.report.active_operator_id)

        field_names = {field.name for field in Report._meta.fields}
        self.assertEqual(
            field_names,
            {
                "id",
                "state",
                "state_version",
                "current_lease_generation",
                "active_operator_id",
                "received_at",
                "claimed_at",
                "claim_expires_at",
                "response_available_at",
                "terminal_at",
            },
        )

    def test_direct_existing_row_mutation_is_denied(self) -> None:
        self.report.state = ReportState.CLAIMED
        with self.assertRaises(LifecycleTransitionDenied):
            self.report.save()

        lease = self.make_lease()
        lease.state = LeaseState.EXPIRED
        with self.assertRaises(LifecycleTransitionDenied):
            lease.save()

        operation = SecurityOperation.objects.create(
            report=self.report,
            kind=SecurityOperationKind.EMERGENCY_EXPORT,
            bound_report_version=0,
            fence_token=1,
            actor_id=self.operator_id,
        )
        operation.state = SecurityOperationState.ACTIVE
        with self.assertRaises(LifecycleTransitionDenied):
            operation.save()

    def test_report_database_constraints_reject_invalid_shapes(self) -> None:
        invalid_updates = (
            {"state": "UNKNOWN"},
            {"state": ReportState.CLAIMED},
            {"state": ReportState.RESPONSE_AVAILABLE},
            {"state": ReportState.DESTROYED},
        )
        for updates in invalid_updates:
            with self.subTest(updates=updates):
                with self.assertRaises(IntegrityError):
                    with transaction.atomic():
                        Report.objects.filter(id=self.report.id).update(**updates)

    def test_database_enforces_one_active_report_per_operator(self) -> None:
        second_report = Report.objects.create()
        claim_values = {
            "state": ReportState.CLAIMED,
            "state_version": 1,
            "active_operator_id": self.operator_id,
            "claimed_at": self.now,
            "claim_expires_at": self.now + timedelta(minutes=5),
        }
        Report.objects.filter(id=self.report.id).update(**claim_values)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Report.objects.filter(id=second_report.id).update(**claim_values)

    def test_database_enforces_one_active_lease_per_report_and_operator(self) -> None:
        self.make_lease()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.make_lease(operator_id=uuid4(), generation=2)

        second_report = Report.objects.create()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.make_lease(report=second_report, generation=1)

    def test_database_rejects_invalid_lease_time_order(self) -> None:
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ReportLease.objects.create(
                    report=self.report,
                    operator_id=self.operator_id,
                    generation=1,
                    opened_at=self.now,
                    last_activity_at=self.now + timedelta(hours=2),
                    absolute_expires_at=self.now + timedelta(hours=1),
                )

    def test_operation_fence_and_idempotency_are_unique(self) -> None:
        first = SecurityOperation.objects.create(
            report=self.report,
            kind=SecurityOperationKind.FINALIZE_RESPONSE,
            bound_report_version=0,
            fence_token=1,
            actor_id=self.operator_id,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SecurityOperation.objects.create(
                    report=self.report,
                    kind=SecurityOperationKind.EMERGENCY_EXPORT,
                    bound_report_version=0,
                    fence_token=1,
                    actor_id=uuid4(),
                )

        second_report = Report.objects.create()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SecurityOperation.objects.create(
                    report=second_report,
                    kind=SecurityOperationKind.DELETE_REPORT_FLOOD,
                    bound_report_version=0,
                    fence_token=1,
                    idempotency_id=first.idempotency_id,
                    actor_id=uuid4(),
                )

    def test_database_allows_only_one_active_operation_fence(self) -> None:
        first = SecurityOperation.objects.create(
            report=self.report,
            kind=SecurityOperationKind.FINALIZE_RESPONSE,
            bound_report_version=0,
            fence_token=1,
            actor_id=self.operator_id,
        )
        second = SecurityOperation.objects.create(
            report=self.report,
            kind=SecurityOperationKind.EMERGENCY_EXPORT,
            bound_report_version=0,
            fence_token=2,
            actor_id=self.operator_id,
        )
        SecurityOperation.objects.filter(id=first.id).update(
            state=SecurityOperationState.ACTIVE,
            state_version=1,
            activated_at=self.now,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SecurityOperation.objects.filter(id=second.id).update(
                    state=SecurityOperationState.ACTIVE,
                    state_version=1,
                    activated_at=self.now,
                )

    def test_operation_lease_binding_is_all_or_nothing(self) -> None:
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SecurityOperation.objects.create(
                    report=self.report,
                    kind=SecurityOperationKind.EMERGENCY_EXPORT,
                    bound_report_version=0,
                    fence_token=1,
                    actor_id=self.operator_id,
                    lease_generation=1,
                )

    def test_no_route_view_admin_or_background_worker_is_enabled(self) -> None:
        self.assertEqual(
            {pattern.name for pattern in urls.urlpatterns},
            {
                "reporter-home",
                "reporter-status",
                "reporter-submit",
                "reporter-response",
                "operator-console",
            },
        )
        app_path = Path(Report._meta.app_config.path)
        for forbidden_file in (
            "admin.py",
            "tasks.py",
            "urls.py",
            "views.py",
        ):
            with self.subTest(file=forbidden_file):
                self.assertFalse((app_path / forbidden_file).exists())
