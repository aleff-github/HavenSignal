"""Negative tests for inert submission-audit descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1,
    SUBMISSION_AUDIT_FAILED_AUTHORIZATION_WINDOW_MS,
    SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1,
    SUBMISSION_AUDIT_PHASES_V1,
    SUBMISSION_AUDIT_PROFILE_VERSION,
    SUBMISSION_AUDIT_RECEIVED_AUTHORIZATION_WINDOW_MS,
    SUBMISSION_AUDIT_REQUESTED_AUTHORIZATION_WINDOW_MS,
    AuditEventType,
    StructurallyValidSubmissionAuditProfileV1,
    SubmissionAuditAllowedPayloadField,
    SubmissionAuditDescriptorRejected,
    SubmissionAuditForbiddenPayloadField,
    SubmissionAuditPayloadPolicyV1,
    SubmissionAuditPhase,
    SubmissionAuditPhaseDescriptorV1,
    SubmissionAuditProfileV1,
    SubmissionAuditTiming,
    expected_submission_audit_profile_v1,
    validate_submission_audit_payload_policy_v1,
    validate_submission_audit_phase_descriptor_v1,
    validate_submission_audit_profile_v1,
)


class SubmissionAuditRegistryTests(SimpleTestCase):
    def test_constants_and_phase_order_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_AUDIT_PROFILE_VERSION, 1)
        self.assertEqual(
            SUBMISSION_AUDIT_REQUESTED_AUTHORIZATION_WINDOW_MS,
            15 * 60 * 1000,
        )
        self.assertEqual(SUBMISSION_AUDIT_RECEIVED_AUTHORIZATION_WINDOW_MS, 60_000)
        self.assertEqual(SUBMISSION_AUDIT_FAILED_AUTHORIZATION_WINDOW_MS, 0)
        self.assertEqual(
            tuple(phase.phase for phase in SUBMISSION_AUDIT_PHASES_V1),
            (
                SubmissionAuditPhase.ACCEPTANCE_REQUESTED,
                SubmissionAuditPhase.RECEIVED,
                SubmissionAuditPhase.ACCEPTANCE_FAILED,
            ),
        )
        self.assertEqual(
            tuple(phase.audit_event_type for phase in SUBMISSION_AUDIT_PHASES_V1),
            (
                AuditEventType.SUBMISSION_ACCEPTANCE_REQUESTED,
                AuditEventType.SUBMISSION_RECEIVED,
                AuditEventType.SUBMISSION_ACCEPTANCE_FAILED,
            ),
        )
        self.assertEqual(
            tuple(phase.required_timing for phase in SUBMISSION_AUDIT_PHASES_V1),
            (
                SubmissionAuditTiming.BEFORE_KEY_OR_MATERIAL_CREATION,
                SubmissionAuditTiming.AFTER_STAGED_CIPHERTEXT_DURABILITY,
                SubmissionAuditTiming.BEST_EFFORT_ABORT_EVIDENCE,
            ),
        )

    def test_payload_policy_is_exact(self) -> None:
        self.assertEqual(
            tuple(field.value for field in SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1),
            (
                "SYSTEM_GENERATED_IDENTIFIER",
                "EVENT_OPERATION_CODE",
                "ATTEMPT_STATE",
                "ATTEMPT_VERSION",
                "CALLER_IDENTITY",
                "IDEMPOTENCY_CONTEXT",
                "ANTI_REPLAY_CONTEXT",
            ),
        )
        self.assertEqual(
            tuple(field.value for field in SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1),
            (
                "REPORT_TEXT",
                "ATTACHMENT_CONTENT",
                "ORIGINAL_FILENAME",
                "FILE_METADATA",
                "RECOVERY_SECRET",
                "CRYPTOGRAPHIC_KEY",
                "REQUEST_HEADER",
                "RAW_ERROR",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_audit_profile_v1(
            expected_submission_audit_profile_v1()
        )
        self.assertIsInstance(validated, StructurallyValidSubmissionAuditProfileV1)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.creates_audit_receipt)
        self.assertFalse(validated.verifies_audit_receipt)
        self.assertFalse(validated.inspects_attempt_state)
        self.assertFalse(validated.calls_audit_service)
        self.assertFalse(validated.creates_report_key)
        self.assertFalse(validated.persists_submission_metadata)
        self.assertFalse(validated.authorizes_submission)
        for field_name in (
            "report_text",
            "attachment_content",
            "filename",
            "recovery_secret",
            "key",
            "receipt_bytes",
            "request_headers",
            "raw_error",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionAuditValidationTests(SimpleTestCase):
    def test_phase_descriptor_rejects_drift(self) -> None:
        valid = SUBMISSION_AUDIT_PHASES_V1[0]
        self.assertEqual(validate_submission_audit_phase_descriptor_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, phase=SubmissionAuditPhase.RECEIVED),
            replace(valid, audit_event_type=AuditEventType.SUBMISSION_RECEIVED),
            replace(
                valid,
                required_timing=(
                    SubmissionAuditTiming.AFTER_STAGED_CIPHERTEXT_DURABILITY
                ),
            ),
            replace(valid, authorization_window_ms=60_000),
            replace(valid, durable_receipt_required=1),
            replace(valid, durable_receipt_required=False),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionAuditDescriptorRejected):
                    validate_submission_audit_phase_descriptor_v1(candidate)

    def test_payload_policy_rejects_drift(self) -> None:
        valid = expected_submission_audit_profile_v1().payload_policy
        self.assertEqual(
            validate_submission_audit_payload_policy_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, allowed_fields=SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1[:-1]),
            replace(
                valid,
                allowed_fields=SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1
                + (SubmissionAuditAllowedPayloadField.ATTEMPT_STATE,),
            ),
            replace(
                valid,
                forbidden_fields=SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1[:-1],
            ),
            replace(
                valid,
                forbidden_fields=tuple(
                    field.value
                    for field in SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1
                ),
            ),
            SubmissionAuditPayloadPolicyV1(
                allowed_fields=(
                    SubmissionAuditForbiddenPayloadField.REPORT_TEXT,
                ),
                forbidden_fields=SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1,
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionAuditDescriptorRejected):
                    validate_submission_audit_payload_policy_v1(candidate)

    def test_profile_rejects_changed_phase_order(self) -> None:
        valid = expected_submission_audit_profile_v1()
        self.assertEqual(validate_submission_audit_profile_v1(valid).profile, valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, phases=tuple(reversed(valid.phases))),
            replace(valid, phases=valid.phases[:-1]),
            replace(valid, phases=list(valid.phases)),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionAuditDescriptorRejected):
                    validate_submission_audit_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        descriptor = SUBMISSION_AUDIT_PHASES_V1[0]
        with self.assertRaises(FrozenInstanceError):
            descriptor.authorization_window_ms = 1

        validated = validate_submission_audit_profile_v1(
            expected_submission_audit_profile_v1()
        )
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.appends_audit_event = True

    def test_schema_fields_are_metadata_only(self) -> None:
        self.assertEqual(
            {field.name for field in fields(SubmissionAuditPhaseDescriptorV1)},
            {
                "phase",
                "audit_event_type",
                "required_timing",
                "authorization_window_ms",
                "durable_receipt_required",
            },
        )
        self.assertEqual(
            {field.name for field in fields(SubmissionAuditProfileV1)},
            {"scheme_version", "phases", "payload_policy"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_AUDIT_SENTINEL"
        valid = SUBMISSION_AUDIT_PHASES_V1[0]
        with self.assertRaises(SubmissionAuditDescriptorRejected) as raised:
            validate_submission_audit_phase_descriptor_v1(
                replace(valid, phase=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "submission_audit_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
