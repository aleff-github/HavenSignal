"""PostgreSQL preparation executor and fail-closed backend tests."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from report_lifecycle.bindings import (
    LeaseBindingSnapshot,
    ReportBindingSnapshot,
    SecurityOperationCommand,
    ValidatedSecurityOperationBinding,
    validate_inert_security_operation_binding,
)
from report_lifecycle.errors import LifecyclePersistenceUnavailable
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.persistence import (
    LifecycleBackendCapabilities,
    PreparedSecurityOperation,
    inspect_lifecycle_backend,
    persist_validated_security_operation,
    require_postgresql_transition_backend,
)
from report_lifecycle.states import (
    LeaseState,
    ReportState,
    SecurityOperationKind,
    SecurityOperationState,
)


class LifecyclePersistenceBoundaryTests(TransactionTestCase):
    reset_sequences = False

    def setUp(self) -> None:
        self.now = timezone.now()
        self.operator_id = uuid4()
        self.report = Report.objects.create()
        Report.objects.filter(id=self.report.id).update(
            state=ReportState.OPEN,
            state_version=3,
            current_lease_generation=2,
            active_operator_id=self.operator_id,
        )
        self.report.refresh_from_db()
        self.lease = ReportLease.objects.create(
            report=self.report,
            operator_id=self.operator_id,
            generation=2,
            opened_at=self.now - timedelta(minutes=10),
            last_activity_at=self.now - timedelta(minutes=1),
            absolute_expires_at=self.now + timedelta(minutes=50),
        )
        self.command = SecurityOperationCommand(
            operation_id=uuid4(),
            idempotency_id=uuid4(),
            kind=SecurityOperationKind.EMERGENCY_EXPORT,
            report_id=self.report.id,
            expected_report_version=3,
            actor_id=self.operator_id,
            lease_id=self.lease.id,
            lease_generation=2,
        )
        self.binding = self._validated_binding()

    def _validated_binding(
        self,
        command: SecurityOperationCommand | None = None,
    ) -> ValidatedSecurityOperationBinding:
        with patch("report_lifecycle.transitions.timezone.now", return_value=self.now):
            return validate_inert_security_operation_binding(
                command=command or self.command,
                report=ReportBindingSnapshot(
                    report_id=self.report.id,
                    state=self.report.state,
                    state_version=self.report.state_version,
                    current_lease_generation=self.report.current_lease_generation,
                    active_operator_id=self.report.active_operator_id,
                ),
                lease=LeaseBindingSnapshot(
                    lease_id=self.lease.id,
                    report_id=self.report.id,
                    operator_id=self.lease.operator_id,
                    generation=self.lease.generation,
                    state=self.lease.state,
                    state_version=self.lease.state_version,
                    opened_at=self.lease.opened_at,
                    last_activity_at=self.lease.last_activity_at,
                    absolute_expires_at=self.lease.absolute_expires_at,
                ),
            )

    def assert_persistence_denied(
        self,
        binding: object,
        *,
        using: str = "default",
    ) -> None:
        with self.assertRaises(LifecyclePersistenceUnavailable) as raised:
            persist_validated_security_operation(binding=binding, using=using)
        self.assertEqual(str(raised.exception), "lifecycle_persistence_unavailable")

    def test_configured_backend_capabilities_are_explicit(self) -> None:
        capabilities = inspect_lifecycle_backend()
        if capabilities.vendor == "sqlite":
            self.assertFalse(capabilities.supports_row_locks)
            with self.assertRaises(LifecyclePersistenceUnavailable):
                require_postgresql_transition_backend()
            return
        self.assertEqual(capabilities.vendor, "postgresql")
        self.assertTrue(capabilities.supports_transactions)
        self.assertTrue(capabilities.supports_row_locks)
        self.assertTrue(capabilities.supports_partial_indexes)
        self.assertEqual(require_postgresql_transition_backend(), capabilities)

    def test_prepare_is_postgresql_only_and_metadata_only(self) -> None:
        if connection.vendor != "postgresql":
            self.assert_persistence_denied(self.binding)
            self.assertEqual(SecurityOperation.objects.count(), 0)
            return

        prepared = persist_validated_security_operation(binding=self.binding)
        self.assertEqual(
            {field.name for field in fields(prepared)},
            {
                "operation_id",
                "report_id",
                "idempotency_id",
                "state",
                "bound_report_version",
                "fence_token",
                "lease_id",
                "lease_generation",
            },
        )
        self.assertEqual(prepared.operation_id, self.command.operation_id)
        self.assertEqual(prepared.report_id, self.report.id)
        self.assertEqual(prepared.idempotency_id, self.command.idempotency_id)
        self.assertEqual(prepared.state, SecurityOperationState.PREPARED)
        self.assertEqual(prepared.bound_report_version, 3)
        self.assertEqual(prepared.fence_token, 1)
        self.assertEqual(prepared.lease_id, self.lease.id)
        self.assertEqual(prepared.lease_generation, 2)
        with self.assertRaises(FrozenInstanceError):
            prepared.fence_token = 2

        operation = SecurityOperation.objects.get(id=prepared.operation_id)
        self.assertEqual(operation.state, SecurityOperationState.PREPARED)
        self.assertIsNone(operation.activated_at)
        self.assertIsNone(operation.terminal_at)
        self.report.refresh_from_db()
        self.lease.refresh_from_db()
        self.assertEqual(self.report.state, ReportState.OPEN)
        self.assertEqual(self.report.state_version, 3)
        self.assertEqual(self.lease.state, LeaseState.ACTIVE)
        self.assertEqual(self.lease.last_activity_at, self.now - timedelta(minutes=1))

    def test_locked_state_is_revalidated_and_stale_binding_is_denied(self) -> None:
        Report.objects.filter(id=self.report.id).update(state_version=4)
        self.assert_persistence_denied(self.binding)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_tampered_derived_binding_is_denied(self) -> None:
        tampered = replace(
            self.binding,
            report_state=ReportState.FINALIZING,
        )
        self.assert_persistence_denied(tampered)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_one_nonterminal_operation_per_report_is_enforced(self) -> None:
        if connection.vendor != "postgresql":
            self.assert_persistence_denied(self.binding)
            return
        first = persist_validated_security_operation(binding=self.binding)
        second_command = replace(
            self.command,
            operation_id=uuid4(),
            idempotency_id=uuid4(),
        )
        self.assert_persistence_denied(self._validated_binding(second_command))
        self.assertEqual(
            list(SecurityOperation.objects.values_list("id", flat=True)),
            [first.operation_id],
        )

    def test_fence_is_monotonic_after_terminal_operation(self) -> None:
        if connection.vendor != "postgresql":
            self.assert_persistence_denied(self.binding)
            return
        first = persist_validated_security_operation(binding=self.binding)
        SecurityOperation.objects.filter(id=first.operation_id).update(
            state=SecurityOperationState.ABORTED,
            terminal_at=self.now,
        )
        second_command = replace(
            self.command,
            operation_id=uuid4(),
            idempotency_id=uuid4(),
        )
        second = persist_validated_security_operation(
            binding=self._validated_binding(second_command)
        )
        self.assertEqual(second.fence_token, 2)

    def test_mocked_capabilities_do_not_enable_sqlite(self) -> None:
        capabilities = LifecycleBackendCapabilities(
            alias="default",
            vendor="postgresql",
            supports_transactions=True,
            supports_row_locks=True,
            supports_partial_indexes=True,
        )
        with patch(
            "report_lifecycle.persistence.require_postgresql_transition_backend",
            return_value=capabilities,
        ):
            if connection.vendor == "postgresql":
                prepared = persist_validated_security_operation(binding=self.binding)
                self.assertIsInstance(prepared, PreparedSecurityOperation)
            else:
                self.assert_persistence_denied(self.binding)

    def test_invalid_input_and_alias_fail_without_writes(self) -> None:
        with patch(
            "report_lifecycle.persistence.require_postgresql_transition_backend"
        ) as backend_check:
            self.assert_persistence_denied(object())
        backend_check.assert_not_called()
        self.assert_persistence_denied(self.binding, using="unknown")
        self.assertEqual(SecurityOperation.objects.count(), 0)
