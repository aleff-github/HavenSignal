"""Negative and structural tests for the inert administrator-alert profile."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    ALERT_SEVERITY_BY_TYPE,
    MAX_CBOR_UINT,
    AlertAcceptanceConfirmationV1,
    AlertAcknowledgementReferenceV1,
    AlertActorReferenceV1,
    AlertDeliveryState,
    AlertDescriptorRejected,
    AlertOperationReferenceV1,
    AlertProfileReferenceV1,
    AlertSeverity,
    AlertType,
    AuditActorKind,
    validate_alert_acceptance_confirmation_v1,
    validate_alert_acknowledgement_reference_v1,
    validate_alert_actor_reference_v1,
    validate_alert_delivery_state_v1,
    validate_alert_operation_reference_v1,
    validate_alert_profile_reference_v1,
)


EXPECTED_ALERT_SEVERITIES = {
    "AUDIT_GAP_DETECTED": "CRITICAL",
    "AUDIT_FORK_OR_ROLLBACK": "CRITICAL",
    "AUDIT_CESSATION": "CRITICAL",
    "AUDIT_INCLUSION_LATE": "CRITICAL",
    "CIPHERTEXT_DELETE_PERSISTENT_FAILURE": "HIGH",
    "EMERGENCY_EXPORT_REQUESTED": "CRITICAL",
    "EXPORT_STAGING_CLEANUP_FAILURE": "CRITICAL",
    "KEY_STATE_MISMATCH": "CRITICAL",
    "WEBAUTHN_COUNTER_REGRESSION": "CRITICAL",
    "SECURITY_CREDENTIAL_CHANGE": "HIGH",
}


class AlertRegistryTests(SimpleTestCase):
    def test_alert_type_severity_and_delivery_registries_are_exact(self) -> None:
        self.assertEqual(
            {
                alert_type.value: severity.value
                for alert_type, severity in ALERT_SEVERITY_BY_TYPE.items()
            },
            EXPECTED_ALERT_SEVERITIES,
        )
        self.assertEqual(
            {alert_type.value for alert_type in AlertType},
            set(EXPECTED_ALERT_SEVERITIES),
        )
        self.assertEqual(
            {severity.value for severity in AlertSeverity},
            {"HIGH", "CRITICAL"},
        )
        self.assertEqual(
            {state.value for state in AlertDeliveryState},
            {"QUEUED", "DELIVERED", "DELIVERY_RETRY"},
        )

    def test_severity_is_fixed_by_alert_type(self) -> None:
        for alert_type, severity in ALERT_SEVERITY_BY_TYPE.items():
            with self.subTest(alert_type=alert_type):
                validated = validate_alert_profile_reference_v1(
                    AlertProfileReferenceV1(
                        alert_type=alert_type.value,
                        severity=severity.value,
                    )
                )
                self.assertEqual(validated.alert_type, alert_type)
                self.assertEqual(validated.severity, severity)

                wrong = (
                    AlertSeverity.HIGH
                    if severity == AlertSeverity.CRITICAL
                    else AlertSeverity.CRITICAL
                )
                with self.assertRaises(AlertDescriptorRejected):
                    validate_alert_profile_reference_v1(
                        AlertProfileReferenceV1(alert_type, wrong)
                    )

    def test_registry_is_immutable_and_unknown_type_is_controlled(self) -> None:
        with self.assertRaises(TypeError):
            ALERT_SEVERITY_BY_TYPE[AlertType.AUDIT_CESSATION] = AlertSeverity.HIGH

        sentinel = "REPORT_TEXT_SENTINEL"
        with self.assertRaises(AlertDescriptorRejected) as raised:
            validate_alert_profile_reference_v1(
                AlertProfileReferenceV1(sentinel, "CRITICAL")
            )
        self.assertEqual(str(raised.exception), "alert_descriptor_rejected")
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

        self.assertEqual(
            validate_alert_delivery_state_v1("DELIVERY_RETRY"),
            AlertDeliveryState.DELIVERY_RETRY,
        )
        with self.assertRaises(AlertDescriptorRejected):
            validate_alert_delivery_state_v1("CALLER_SELECTED_STATE")


class AlertRequestComponentTests(SimpleTestCase):
    def test_component_fields_are_closed_and_content_free(self) -> None:
        self.assertEqual(
            {field.name for field in fields(AlertProfileReferenceV1)},
            {"alert_type", "severity"},
        )
        self.assertEqual(
            {field.name for field in fields(AlertActorReferenceV1)},
            {"actor_kind", "actor_id"},
        )
        self.assertEqual(
            {field.name for field in fields(AlertOperationReferenceV1)},
            {"operation_id", "idempotency_id", "source_event_id"},
        )

    def test_actor_kind_and_identifier_pairing_is_exact(self) -> None:
        anonymous = validate_alert_actor_reference_v1(
            AlertActorReferenceV1("NONE", None)
        )
        self.assertEqual(anonymous.actor_kind, AuditActorKind.NONE)

        service = validate_alert_actor_reference_v1(
            AlertActorReferenceV1("SERVICE", b"S" * 16)
        )
        self.assertEqual(service.actor_kind, AuditActorKind.SERVICE)

        for reference in (
            AlertActorReferenceV1("NONE", b"A" * 16),
            AlertActorReferenceV1("OPERATOR", None),
            AlertActorReferenceV1("APPLICATION_ADMIN", b"A" * 15),
            AlertActorReferenceV1("SERVICE", bytearray(b"S" * 16)),
            AlertActorReferenceV1("UNKNOWN", None),
        ):
            with self.subTest(reference=reference):
                with self.assertRaises(AlertDescriptorRejected):
                    validate_alert_actor_reference_v1(reference)

    def test_operation_identifiers_use_exact_immutable_lengths(self) -> None:
        valid = AlertOperationReferenceV1(
            operation_id=b"O" * 16,
            idempotency_id=b"I" * 16,
            source_event_id=b"E" * 16,
        )
        self.assertEqual(validate_alert_operation_reference_v1(valid), valid)
        self.assertIsNone(
            validate_alert_operation_reference_v1(
                replace(valid, source_event_id=None)
            ).source_event_id
        )

        for reference in (
            replace(valid, operation_id=b"O" * 15),
            replace(valid, idempotency_id=b"I" * 17),
            replace(valid, source_event_id=b"E" * 15),
            replace(valid, operation_id=bytearray(b"O" * 16)),
        ):
            with self.subTest(reference=reference):
                with self.assertRaises(AlertDescriptorRejected):
                    validate_alert_operation_reference_v1(reference)

    def test_request_components_are_immutable(self) -> None:
        reference = AlertOperationReferenceV1(b"O" * 16, b"I" * 16, None)
        with self.assertRaises(FrozenInstanceError):
            reference.operation_id = b"X" * 16


class AlertAcceptanceAndAcknowledgementTests(SimpleTestCase):
    def test_acceptance_confirmation_is_only_structural(self) -> None:
        confirmation = AlertAcceptanceConfirmationV1(
            alert_id=b"A" * 16,
            accepted_at_ms=1_800_000_000_000,
        )
        validated = validate_alert_acceptance_confirmation_v1(confirmation)
        self.assertEqual(validated.confirmation, confirmation)
        self.assertFalse(validated.proves_durable_acceptance)
        self.assertFalse(validated.authorizes_protected_action)
        self.assertFalse(hasattr(validated, "smtp_delivery"))
        self.assertFalse(hasattr(validated, "receipt_signature"))

    def test_acceptance_fields_reject_wrong_types_lengths_and_uints(self) -> None:
        valid = AlertAcceptanceConfirmationV1(b"A" * 16, 1)
        for confirmation in (
            replace(valid, alert_id=b"A" * 15),
            replace(valid, alert_id=bytearray(b"A" * 16)),
            replace(valid, accepted_at_ms=True),
            replace(valid, accepted_at_ms=-1),
            replace(valid, accepted_at_ms=MAX_CBOR_UINT + 1),
        ):
            with self.subTest(confirmation=confirmation):
                with self.assertRaises(AlertDescriptorRejected):
                    validate_alert_acceptance_confirmation_v1(confirmation)

    def test_acknowledgement_fields_are_both_nil_or_both_present(self) -> None:
        empty = AlertAcknowledgementReferenceV1(None, None)
        self.assertEqual(
            validate_alert_acknowledgement_reference_v1(empty),
            empty,
        )
        complete = AlertAcknowledgementReferenceV1(1_800_000_000_000, b"D" * 16)
        self.assertEqual(
            validate_alert_acknowledgement_reference_v1(complete),
            complete,
        )

        for reference in (
            AlertAcknowledgementReferenceV1(None, b"D" * 16),
            AlertAcknowledgementReferenceV1(1, None),
            AlertAcknowledgementReferenceV1(True, b"D" * 16),
            AlertAcknowledgementReferenceV1(1, b"D" * 15),
        ):
            with self.subTest(reference=reference):
                with self.assertRaises(AlertDescriptorRejected):
                    validate_alert_acknowledgement_reference_v1(reference)

    def test_structural_results_are_immutable(self) -> None:
        result = validate_alert_acceptance_confirmation_v1(
            AlertAcceptanceConfirmationV1(b"A" * 16, 1)
        )
        with self.assertRaises(FrozenInstanceError):
            result.confirmation = AlertAcceptanceConfirmationV1(b"B" * 16, 2)
