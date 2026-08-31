"""Sequence and denial tests for the inert operator-deletion shell."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from report_lifecycle.bindings import (
    LeaseBindingSnapshot,
    ReportBindingSnapshot,
    SecurityOperationCommand,
    validate_inert_security_operation_binding,
)
from report_lifecycle.deletion import (
    OPERATOR_DELETION_SEQUENCE,
    OPERATOR_DELETION_TRANSITIONS,
    InertOperatorDeletionStepPlan,
    OperatorDeletionCheckpoint,
    execute_operator_deletion_step,
    plan_inert_operator_deletion_step,
)
from report_lifecycle.errors import (
    DeletionOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.states import LeaseState, ReportState, SecurityOperationKind


class InertOperatorDeletionOrchestrationTests(TestCase):
    def setUp(self) -> None:
        now = timezone.now()
        report_id = uuid4()
        operator_id = uuid4()
        lease_id = uuid4()
        command = SecurityOperationCommand(
            operation_id=uuid4(),
            idempotency_id=uuid4(),
            kind=SecurityOperationKind.DELETE_REPORT,
            report_id=report_id,
            expected_report_version=11,
            actor_id=operator_id,
            lease_id=lease_id,
            lease_generation=4,
        )
        report = ReportBindingSnapshot(
            report_id=report_id,
            state=ReportState.OPEN,
            state_version=11,
            current_lease_generation=4,
            active_operator_id=operator_id,
        )
        lease = LeaseBindingSnapshot(
            lease_id=lease_id,
            report_id=report_id,
            operator_id=operator_id,
            generation=4,
            state=LeaseState.ACTIVE,
            state_version=2,
            opened_at=now - timedelta(minutes=5),
            last_activity_at=now - timedelta(minutes=1),
            absolute_expires_at=now + timedelta(minutes=55),
        )
        self.binding = validate_inert_security_operation_binding(
            command=command,
            report=report,
            lease=lease,
        )

    def test_sequence_matches_the_approved_operator_order_exactly(self) -> None:
        self.assertEqual(
            OPERATOR_DELETION_SEQUENCE,
            tuple(OperatorDeletionCheckpoint),
        )
        self.assertEqual(len(OPERATOR_DELETION_SEQUENCE), 11)
        for index, checkpoint in enumerate(OPERATOR_DELETION_SEQUENCE):
            expected = (
                frozenset({OPERATOR_DELETION_SEQUENCE[index + 1]})
                if index + 1 < len(OPERATOR_DELETION_SEQUENCE)
                else frozenset()
            )
            self.assertEqual(OPERATOR_DELETION_TRANSITIONS[checkpoint], expected)

    def test_every_approved_edge_produces_a_non_destructive_plan(self) -> None:
        for source, target in zip(
            OPERATOR_DELETION_SEQUENCE,
            OPERATOR_DELETION_SEQUENCE[1:],
        ):
            with self.subTest(source=source, target=target):
                plan = plan_inert_operator_deletion_step(
                    binding=self.binding,
                    source_checkpoint=source,
                    target_checkpoint=target,
                )
                self.assertFalse(plan.authorizes_execution)
                self.assertFalse(plan.persists_checkpoint)
                self.assertFalse(plan.destroys_key_or_content)
                self.assertEqual(plan.source_checkpoint, source)
                self.assertEqual(plan.target_checkpoint, target)

    def test_every_skip_reverse_repeat_and_terminal_edge_is_denied(self) -> None:
        for source in OperatorDeletionCheckpoint:
            for target in OperatorDeletionCheckpoint:
                if target in OPERATOR_DELETION_TRANSITIONS[source]:
                    continue
                with self.subTest(source=source, target=target):
                    with self.assertRaises(LifecycleTransitionDenied):
                        plan_inert_operator_deletion_step(
                            binding=self.binding,
                            source_checkpoint=source,
                            target_checkpoint=target,
                        )

    def test_strings_and_unknown_checkpoints_are_denied_without_echo(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            plan_inert_operator_deletion_step(
                binding=self.binding,
                source_checkpoint=sentinel,
                target_checkpoint=(
                    OperatorDeletionCheckpoint.OPEN_CONTEXT_INPUTS_AND_CAPTCHA_VALIDATED
                ),
            )
        self.assertNotIn(sentinel, repr(raised.exception))

    def test_forged_wrong_state_or_wrong_operation_binding_is_denied(self) -> None:
        wrong_command = replace(
            self.binding.command,
            kind=SecurityOperationKind.DELETE_REPORT_FLOOD,
        )
        wrong_bindings = (
            object(),
            replace(self.binding, command=wrong_command),
            replace(
                self.binding,
                command=replace(self.binding.command, idempotency_id="not-a-uuid"),
            ),
            replace(self.binding, report_state=ReportState.DELETING),
            replace(self.binding, report_state_version=True),
            replace(self.binding, lease_activity=None),
            replace(self.binding, validated_at="browser-time"),
            replace(
                self.binding,
                lease_activity=replace(
                    self.binding.lease_activity,
                    next_activity_at="browser-time",
                ),
            ),
            replace(
                self.binding,
                validated_at=self.binding.validated_at + timedelta(seconds=1),
            ),
        )
        for binding in wrong_bindings:
            with self.subTest(binding=binding):
                with self.assertRaises(LifecycleTransitionDenied):
                    plan_inert_operator_deletion_step(
                        binding=binding,
                        source_checkpoint=OperatorDeletionCheckpoint.REQUEST_RECEIVED,
                        target_checkpoint=(
                            OperatorDeletionCheckpoint
                            .OPEN_CONTEXT_INPUTS_AND_CAPTCHA_VALIDATED
                        ),
                    )

    def test_plan_fields_are_closed_content_free_and_immutable(self) -> None:
        plan = plan_inert_operator_deletion_step(
            binding=self.binding,
            source_checkpoint=OperatorDeletionCheckpoint.REQUEST_RECEIVED,
            target_checkpoint=(
                OperatorDeletionCheckpoint.OPEN_CONTEXT_INPUTS_AND_CAPTCHA_VALIDATED
            ),
        )
        self.assertEqual(
            {field.name for field in fields(plan)},
            {
                "operation_id",
                "idempotency_id",
                "report_id",
                "operator_id",
                "lease_id",
                "report_state_version",
                "lease_generation",
                "source_checkpoint",
                "target_checkpoint",
            },
        )
        with self.assertRaises(FrozenInstanceError):
            plan.report_state_version = 12
        with self.assertRaises(TypeError):
            OPERATOR_DELETION_TRANSITIONS[
                OperatorDeletionCheckpoint.REQUEST_RECEIVED
            ] = frozenset()

    def test_executor_always_fails_closed_without_database_writes(self) -> None:
        plan = plan_inert_operator_deletion_step(
            binding=self.binding,
            source_checkpoint=OperatorDeletionCheckpoint.REQUEST_RECEIVED,
            target_checkpoint=(
                OperatorDeletionCheckpoint.OPEN_CONTEXT_INPUTS_AND_CAPTCHA_VALIDATED
            ),
        )
        for value in (plan, object()):
            with self.subTest(value=value):
                with self.assertRaises(
                    DeletionOrchestrationUnavailable
                ) as raised:
                    execute_operator_deletion_step(plan=value)
                self.assertEqual(
                    str(raised.exception),
                    "deletion_orchestration_unavailable",
                )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_no_checkpoint_is_a_report_lifecycle_state(self) -> None:
        self.assertTrue(
            set(
                checkpoint.value for checkpoint in OperatorDeletionCheckpoint
            ).isdisjoint(ReportState.values)
        )
        self.assertNotIn(
            "DELETING",
            {item.value for item in OperatorDeletionCheckpoint},
        )
