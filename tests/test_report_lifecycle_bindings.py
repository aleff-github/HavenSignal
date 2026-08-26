"""Cross-object binding and fail-closed persistence boundary tests."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import SimpleTestCase
from django.utils import timezone

from report_lifecycle.bindings import (
    OPERATION_BINDING_POLICIES,
    LeaseBindingSnapshot,
    OperationBindingPolicy,
    ReportBindingSnapshot,
    SecurityOperationCommand,
    ValidatedSecurityOperationBinding,
    validate_inert_security_operation_binding,
)
from report_lifecycle.errors import LifecycleTransitionDenied
from report_lifecycle.states import LeaseState, ReportState, SecurityOperationKind


class OperationBindingValidationTests(SimpleTestCase):
    def setUp(self) -> None:
        self.now = timezone.now()
        self.report_id = uuid4()
        self.operator_id = uuid4()
        self.lease_id = uuid4()
        self.report = ReportBindingSnapshot(
            report_id=self.report_id,
            state=ReportState.OPEN,
            state_version=11,
            current_lease_generation=7,
            active_operator_id=self.operator_id,
        )
        self.lease = LeaseBindingSnapshot(
            lease_id=self.lease_id,
            report_id=self.report_id,
            operator_id=self.operator_id,
            generation=7,
            state=LeaseState.ACTIVE,
            state_version=2,
            opened_at=self.now - timedelta(minutes=10),
            last_activity_at=self.now - timedelta(minutes=1),
            absolute_expires_at=self.now + timedelta(minutes=50),
        )
        self.command = SecurityOperationCommand(
            operation_id=uuid4(),
            idempotency_id=uuid4(),
            kind=SecurityOperationKind.FINALIZE_RESPONSE,
            report_id=self.report_id,
            expected_report_version=11,
            actor_id=self.operator_id,
            lease_id=self.lease_id,
            lease_generation=7,
        )

    def validate(
        self,
        *,
        command: SecurityOperationCommand | None = None,
        report: ReportBindingSnapshot | None = None,
        lease: LeaseBindingSnapshot | None = None,
        use_default_lease: bool = True,
    ) -> ValidatedSecurityOperationBinding:
        selected_lease = self.lease if use_default_lease and lease is None else lease
        with patch("report_lifecycle.transitions.timezone.now", return_value=self.now):
            return validate_inert_security_operation_binding(
                command=command or self.command,
                report=report or self.report,
                lease=selected_lease,
            )

    def assert_denied(self, **kwargs: object) -> None:
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            self.validate(**kwargs)
        self.assertEqual(str(raised.exception), "lifecycle_transition_denied")

    def test_binding_policy_is_closed_and_exact(self) -> None:
        self.assertEqual(
            OPERATION_BINDING_POLICIES,
            {
                SecurityOperationKind.REOPEN_REPORT: OperationBindingPolicy(
                    ReportState.INTERRUPTED,
                    False,
                ),
                SecurityOperationKind.FINALIZE_RESPONSE: OperationBindingPolicy(
                    ReportState.OPEN,
                    True,
                ),
                SecurityOperationKind.EMERGENCY_EXPORT: OperationBindingPolicy(
                    ReportState.OPEN,
                    True,
                ),
                SecurityOperationKind.DELETE_REPORT: OperationBindingPolicy(
                    ReportState.OPEN,
                    True,
                ),
                SecurityOperationKind.DELETE_REPORT_FLOOD: OperationBindingPolicy(
                    ReportState.SEALED,
                    False,
                ),
            },
        )

    def test_every_open_operation_requires_the_same_exact_active_lease(self) -> None:
        for kind in (
            SecurityOperationKind.FINALIZE_RESPONSE,
            SecurityOperationKind.EMERGENCY_EXPORT,
            SecurityOperationKind.DELETE_REPORT,
        ):
            with self.subTest(kind=kind):
                validated = self.validate(command=replace(self.command, kind=kind))
                self.assertEqual(validated.kind, kind)
                self.assertEqual(validated.report_state, ReportState.OPEN)
                self.assertEqual(validated.report_state_version, 11)
                self.assertEqual(validated.lease_activity.generation, 7)
                self.assertEqual(validated.validated_at, self.now)

    def test_reopen_and_flood_delete_require_no_existing_lease(self) -> None:
        cases = (
            (
                SecurityOperationKind.REOPEN_REPORT,
                ReportState.INTERRUPTED,
            ),
            (
                SecurityOperationKind.DELETE_REPORT_FLOOD,
                ReportState.SEALED,
            ),
        )
        for kind, state in cases:
            with self.subTest(kind=kind):
                report = replace(
                    self.report,
                    state=state,
                    current_lease_generation=7,
                    active_operator_id=None,
                )
                command = replace(
                    self.command,
                    kind=kind,
                    lease_id=None,
                    lease_generation=None,
                )
                with patch("report_lifecycle.bindings.timezone.now", return_value=self.now):
                    validated = self.validate(
                        command=command,
                        report=report,
                        lease=None,
                        use_default_lease=False,
                    )
                self.assertIsNone(validated.lease_activity)
                self.assertEqual(validated.validated_at, self.now)

    def test_report_identifier_version_state_and_actor_must_match(self) -> None:
        cases = (
            {"command": replace(self.command, report_id=uuid4())},
            {"command": replace(self.command, expected_report_version=10)},
            {"command": replace(self.command, actor_id=uuid4())},
            {"report": replace(self.report, report_id=uuid4())},
            {"report": replace(self.report, state=ReportState.FINALIZING)},
            {"report": replace(self.report, state_version=12)},
            {"report": replace(self.report, active_operator_id=uuid4())},
        )
        for values in cases:
            with self.subTest(values=values):
                self.assert_denied(**values)

    def test_lease_identifier_generation_report_and_operator_must_match(self) -> None:
        cases = (
            {"command": replace(self.command, lease_id=uuid4())},
            {"command": replace(self.command, lease_generation=6)},
            {"lease": replace(self.lease, lease_id=uuid4())},
            {"lease": replace(self.lease, generation=6)},
            {"lease": replace(self.lease, report_id=uuid4())},
            {"lease": replace(self.lease, operator_id=uuid4())},
            {"report": replace(self.report, current_lease_generation=8)},
        )
        for values in cases:
            with self.subTest(values=values):
                self.assert_denied(**values)

    def test_inactive_idle_expired_and_future_lease_fail_closed(self) -> None:
        cases = (
            replace(self.lease, state=LeaseState.EXPIRED),
            replace(self.lease, last_activity_at=self.now - timedelta(minutes=5)),
            replace(self.lease, absolute_expires_at=self.now),
            replace(self.lease, last_activity_at=self.now + timedelta(seconds=1)),
        )
        for lease in cases:
            with self.subTest(lease=lease):
                self.assert_denied(lease=lease)

    def test_lease_required_and_lease_forbidden_profiles_fail_closed(self) -> None:
        self.assert_denied(lease=None, use_default_lease=False)

        interrupted = replace(
            self.report,
            state=ReportState.INTERRUPTED,
            active_operator_id=None,
        )
        reopen = replace(self.command, kind=SecurityOperationKind.REOPEN_REPORT)
        self.assert_denied(command=reopen, report=interrupted)

    def test_unknown_or_malformed_values_share_one_denial(self) -> None:
        cases = (
            {"command": replace(self.command, kind="UNKNOWN")},
            {"command": replace(self.command, operation_id="not-a-uuid")},
            {"command": replace(self.command, expected_report_version=True)},
            {"report": replace(self.report, state="UNKNOWN")},
            {"lease": replace(self.lease, state="UNKNOWN")},
        )
        for values in cases:
            with self.subTest(values=values):
                self.assert_denied(**values)

    def test_one_hundred_stale_generation_retries_are_all_denied(self) -> None:
        for generation in range(100, 200):
            with self.subTest(generation=generation):
                self.assert_denied(
                    command=replace(self.command, lease_generation=generation)
                )

    def test_descriptors_are_frozen_and_have_no_sensitive_fields(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.command.actor_id = uuid4()

        forbidden = {
            "attachment",
            "audit",
            "body",
            "content",
            "credential",
            "dek",
            "filename",
            "header",
            "key",
            "note",
            "recovery",
            "secret",
            "ticket",
            "verifier",
        }
        for descriptor in (
            ReportBindingSnapshot,
            LeaseBindingSnapshot,
            SecurityOperationCommand,
            ValidatedSecurityOperationBinding,
        ):
            for field in fields(descriptor):
                with self.subTest(descriptor=descriptor.__name__, field=field.name):
                    self.assertFalse(
                        any(fragment in field.name.lower() for fragment in forbidden)
                    )
