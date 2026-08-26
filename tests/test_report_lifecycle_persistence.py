"""Fail-closed persistence boundary tests for the inert lifecycle slice."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from report_lifecycle.bindings import (
    LeaseBindingSnapshot,
    ReportBindingSnapshot,
    SecurityOperationCommand,
    validate_inert_security_operation_binding,
)
from report_lifecycle.errors import LifecyclePersistenceUnavailable
from report_lifecycle.models import SecurityOperation
from report_lifecycle.persistence import (
    LifecycleBackendCapabilities,
    inspect_lifecycle_backend,
    persist_validated_security_operation,
    require_postgresql_transition_backend,
)
from report_lifecycle.states import LeaseState, ReportState, SecurityOperationKind


class LifecyclePersistenceBoundaryTests(TestCase):
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
            expected_report_version=3,
            actor_id=operator_id,
            lease_id=lease_id,
            lease_generation=2,
        )
        report = ReportBindingSnapshot(
            report_id=report_id,
            state=ReportState.OPEN,
            state_version=3,
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
            opened_at=now - timedelta(minutes=10),
            last_activity_at=now - timedelta(minutes=1),
            absolute_expires_at=now + timedelta(minutes=50),
        )
        with patch("report_lifecycle.transitions.timezone.now", return_value=now):
            self.binding = validate_inert_security_operation_binding(
                command=command,
                report=report,
                lease=lease,
            )

    def test_development_sqlite_backend_is_explicitly_rejected(self) -> None:
        capabilities = inspect_lifecycle_backend()
        self.assertEqual(capabilities.vendor, "sqlite")
        self.assertFalse(capabilities.supports_row_locks)
        with self.assertRaises(LifecyclePersistenceUnavailable) as raised:
            require_postgresql_transition_backend()
        self.assertEqual(
            str(raised.exception),
            "lifecycle_persistence_unavailable",
        )

    def test_validated_binding_still_cannot_write_on_sqlite(self) -> None:
        with self.assertRaises(LifecyclePersistenceUnavailable):
            persist_validated_security_operation(binding=self.binding)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_even_capable_backend_profile_does_not_enable_unreviewed_write(self) -> None:
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
            with self.assertRaises(LifecyclePersistenceUnavailable):
                persist_validated_security_operation(binding=self.binding)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_unvalidated_object_never_reaches_backend_check(self) -> None:
        with patch(
            "report_lifecycle.persistence.require_postgresql_transition_backend"
        ) as backend_check:
            with self.assertRaises(LifecyclePersistenceUnavailable):
                persist_validated_security_operation(binding=object())
        backend_check.assert_not_called()
        self.assertEqual(SecurityOperation.objects.count(), 0)
