"""Sequence and denial tests for the inert Emergency Export shell."""

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
from report_lifecycle.emergency_export import (
    EMERGENCY_EXPORT_SEQUENCE,
    EMERGENCY_EXPORT_TRANSITIONS,
    EmergencyExportCheckpoint,
    InertEmergencyExportStepPlan,
    execute_emergency_export_step,
    plan_inert_emergency_export_step,
)
from report_lifecycle.errors import (
    EmergencyExportOrchestrationUnavailable,
    LifecycleTransitionDenied,
)
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.states import LeaseState, ReportState, SecurityOperationKind


class InertEmergencyExportOrchestrationTests(TestCase):
    def setUp(self) -> None:
        now = timezone.now()
        report_id = uuid4()
        operator_id = uuid4()
        lease_id = uuid4()
        command = SecurityOperationCommand(
            operation_id=uuid4(),
            idempotency_id=uuid4(),
            kind=SecurityOperationKind.EMERGENCY_EXPORT,
            report_id=report_id,
            expected_report_version=5,
            actor_id=operator_id,
            lease_id=lease_id,
            lease_generation=2,
        )
        report = ReportBindingSnapshot(
            report_id=report_id,
            state=ReportState.OPEN,
            state_version=5,
            current_lease_generation=2,
            active_operator_id=operator_id,
        )
        lease = LeaseBindingSnapshot(
            lease_id=lease_id,
            report_id=report_id,
            operator_id=operator_id,
            generation=2,
            state=LeaseState.ACTIVE,
            state_version=0,
            opened_at=now - timedelta(minutes=4),
            last_activity_at=now - timedelta(minutes=1),
            absolute_expires_at=now + timedelta(minutes=56),
        )
        self.binding = validate_inert_security_operation_binding(
            command=command,
            report=report,
            lease=lease,
        )

    def test_sequence_matches_the_approved_order_exactly(self) -> None:
        self.assertEqual(
            EMERGENCY_EXPORT_SEQUENCE,
            tuple(EmergencyExportCheckpoint),
        )
        self.assertEqual(len(EMERGENCY_EXPORT_SEQUENCE), 11)
        for index, checkpoint in enumerate(EMERGENCY_EXPORT_SEQUENCE):
            expected = (
                frozenset({EMERGENCY_EXPORT_SEQUENCE[index + 1]})
                if index + 1 < len(EMERGENCY_EXPORT_SEQUENCE)
                else frozenset()
            )
            self.assertEqual(EMERGENCY_EXPORT_TRANSITIONS[checkpoint], expected)

    def test_every_approved_edge_produces_a_non_authorizing_plan(self) -> None:
        for source, target in zip(
            EMERGENCY_EXPORT_SEQUENCE,
            EMERGENCY_EXPORT_SEQUENCE[1:],
        ):
            with self.subTest(source=source, target=target):
                plan = plan_inert_emergency_export_step(
                    binding=self.binding,
                    source_checkpoint=source,
                    target_checkpoint=target,
                )
                self.assertFalse(plan.authorizes_execution)
                self.assertFalse(plan.persists_checkpoint)
                self.assertFalse(plan.creates_export_artifact)
                self.assertFalse(plan.releases_plaintext)
                self.assertEqual(plan.source_checkpoint, source)
                self.assertEqual(plan.target_checkpoint, target)

    def test_skip_reverse_repeat_and_terminal_edges_are_denied(self) -> None:
        for source in EmergencyExportCheckpoint:
            for target in EmergencyExportCheckpoint:
                if target in EMERGENCY_EXPORT_TRANSITIONS[source]:
                    continue
                with self.subTest(source=source, target=target):
                    with self.assertRaises(LifecycleTransitionDenied):
                        plan_inert_emergency_export_step(
                            binding=self.binding,
                            source_checkpoint=source,
                            target_checkpoint=target,
                        )

    def test_forged_or_wrong_operation_binding_is_denied(self) -> None:
        invalid_bindings = (
            object(),
            replace(
                self.binding,
                command=replace(
                    self.binding.command,
                    kind=SecurityOperationKind.FINALIZE_RESPONSE,
                ),
            ),
            replace(self.binding, report_state=ReportState.FINALIZING),
            replace(self.binding, report_state_version=True),
            replace(self.binding, lease_activity=None),
            replace(self.binding, validated_at="browser-time"),
            replace(
                self.binding,
                lease_activity=replace(
                    self.binding.lease_activity,
                    generation=3,
                ),
            ),
        )
        for binding in invalid_bindings:
            with self.subTest(binding=binding):
                with self.assertRaises(LifecycleTransitionDenied):
                    plan_inert_emergency_export_step(
                        binding=binding,
                        source_checkpoint=EmergencyExportCheckpoint.CONTEXT_VALIDATED,
                        target_checkpoint=(
                            EmergencyExportCheckpoint
                            .REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED
                        ),
                    )

    def test_plan_fields_are_closed_content_free_and_immutable(self) -> None:
        plan = plan_inert_emergency_export_step(
            binding=self.binding,
            source_checkpoint=EmergencyExportCheckpoint.CONTEXT_VALIDATED,
            target_checkpoint=(
                EmergencyExportCheckpoint
                .REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED
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
        self.assertIs(type(plan), InertEmergencyExportStepPlan)
        with self.assertRaises(FrozenInstanceError):
            plan.report_state_version = 6
        with self.assertRaises(TypeError):
            EMERGENCY_EXPORT_TRANSITIONS[
                EmergencyExportCheckpoint.CONTEXT_VALIDATED
            ] = frozenset()

    def test_executor_always_fails_closed_without_database_writes(self) -> None:
        plan = plan_inert_emergency_export_step(
            binding=self.binding,
            source_checkpoint=EmergencyExportCheckpoint.CONTEXT_VALIDATED,
            target_checkpoint=(
                EmergencyExportCheckpoint
                .REQUEST_DESCRIPTOR_FROZEN_AND_STEP_UP_COMPLETED
            ),
        )
        for value in (plan, object()):
            with self.subTest(value=value):
                with self.assertRaises(
                    EmergencyExportOrchestrationUnavailable
                ) as raised:
                    execute_emergency_export_step(plan=value)
                self.assertEqual(
                    str(raised.exception),
                    "emergency_export_orchestration_unavailable",
                )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_untrusted_checkpoint_never_appears_in_error(self) -> None:
        sentinel = "PROTECTED_NOTE_SENTINEL"
        with self.assertRaises(LifecycleTransitionDenied) as raised:
            plan_inert_emergency_export_step(
                binding=self.binding,
                source_checkpoint=sentinel,
                target_checkpoint=EmergencyExportCheckpoint.CONTEXT_VALIDATED,
            )
        self.assertNotIn(sentinel, repr(raised.exception))
