"""Negative tests for inert submission-reconciliation descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_RECONCILIATION_ACTIONS_V1,
    SUBMISSION_RECONCILIATION_ALLOWED_PAYLOAD_FIELDS_V1,
    SUBMISSION_RECONCILIATION_CANDIDATE_STATES_V1,
    SUBMISSION_RECONCILIATION_CLEANUP_ALERT_AFTER_MS,
    SUBMISSION_RECONCILIATION_CLEANUP_RETRY_INTERVAL_MAX_MS,
    SUBMISSION_RECONCILIATION_FORBIDDEN_PAYLOAD_FIELDS_V1,
    SUBMISSION_RECONCILIATION_PROFILE_VERSION,
    SUBMISSION_RECONCILIATION_PROGRESS_DEADLINE_MS,
    SUBMISSION_RECONCILIATION_SCAN_INTERVAL_MAX_MS,
    SUBMISSION_RECONCILIATION_TERMINAL_OUTCOMES_V1,
    AlertType,
    StructurallyValidSubmissionReconciliationProfileV1,
    SubmissionReconciliationAction,
    SubmissionReconciliationActionProfileV1,
    SubmissionReconciliationAllowedPayloadField,
    SubmissionReconciliationCandidateState,
    SubmissionReconciliationDescriptorRejected,
    SubmissionReconciliationForbiddenPayloadField,
    SubmissionReconciliationPayloadPolicyV1,
    SubmissionReconciliationProfileV1,
    SubmissionReconciliationStateProfileV1,
    SubmissionReconciliationTerminalOutcome,
    SubmissionReconciliationTimingProfileV1,
    expected_submission_reconciliation_profile_v1,
    validate_submission_reconciliation_action_profile_v1,
    validate_submission_reconciliation_payload_policy_v1,
    validate_submission_reconciliation_profile_v1,
    validate_submission_reconciliation_state_profile_v1,
    validate_submission_reconciliation_timing_profile_v1,
)


class SubmissionReconciliationRegistryTests(SimpleTestCase):
    def test_timing_constants_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_RECONCILIATION_PROFILE_VERSION, 1)
        self.assertEqual(SUBMISSION_RECONCILIATION_SCAN_INTERVAL_MAX_MS, 60_000)
        self.assertEqual(
            SUBMISSION_RECONCILIATION_PROGRESS_DEADLINE_MS,
            15 * 60 * 1000,
        )
        self.assertEqual(
            SUBMISSION_RECONCILIATION_CLEANUP_RETRY_INTERVAL_MAX_MS,
            5 * 60 * 1000,
        )
        self.assertEqual(
            SUBMISSION_RECONCILIATION_CLEANUP_ALERT_AFTER_MS,
            15 * 60 * 1000,
        )

    def test_state_action_and_outcome_registries_are_exact(self) -> None:
        self.assertEqual(
            tuple(state.value for state in SUBMISSION_RECONCILIATION_CANDIDATE_STATES_V1),
            (
                "READY",
                "PROCESSING",
                "CIPHERTEXT_STAGED",
                "AUDIT_CONFIRMED",
                "ABORTING",
            ),
        )
        self.assertEqual(
            tuple(outcome.value for outcome in SUBMISSION_RECONCILIATION_TERMINAL_OUTCOMES_V1),
            (
                "ACCEPTED_WITH_CREDENTIAL_RESPONSE_UNAVAILABLE",
                "ABORTED_AFTER_SCOPED_CLEANUP",
            ),
        )
        self.assertEqual(
            tuple(action.value for action in SUBMISSION_RECONCILIATION_ACTIONS_V1),
            (
                "SCAN_NONTERMINAL_ATTEMPTS",
                "COMPLETE_EVIDENCED_ACCEPTANCE",
                "ENTER_ABORTING",
                "DESTROY_SCOPED_REPORT_KEY",
                "RETRY_SCOPED_CIPHERTEXT_METADATA_DELETION",
                "END_ABORTED",
                "REQUEST_CIPHERTEXT_DELETE_PERSISTENT_FAILURE_ALERT",
            ),
        )

    def test_payload_policy_is_content_free(self) -> None:
        self.assertEqual(
            tuple(field.value for field in SUBMISSION_RECONCILIATION_ALLOWED_PAYLOAD_FIELDS_V1),
            (
                "SYSTEM_GENERATED_ATTEMPT_IDENTIFIER",
                "ATTEMPT_STATE",
                "ATTEMPT_VERSION",
                "SERVER_TIME",
                "IDEMPOTENCY_CONTEXT",
                "SCOPED_CLEANUP_IDENTIFIER",
                "CONTROLLED_CONDITION_CODE",
            ),
        )
        self.assertEqual(
            tuple(field.value for field in SUBMISSION_RECONCILIATION_FORBIDDEN_PAYLOAD_FIELDS_V1),
            (
                "REPORT_TEXT",
                "ATTACHMENT_CONTENT",
                "ORIGINAL_FILENAME",
                "RECOVERY_SECRET",
                "CREDENTIAL_RESPONSE",
                "CRYPTOGRAPHIC_KEY",
                "CIPHERTEXT_BYTES",
                "AUDIT_RECEIPT_BYTES",
                "REQUEST_HEADER",
                "RAW_ERROR",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_reconciliation_profile_v1(
            expected_submission_reconciliation_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidSubmissionReconciliationProfileV1,
        )
        self.assertFalse(validated.scans_report_content)
        self.assertFalse(validated.decrypts_plaintext)
        self.assertFalse(validated.creates_credentials)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.verifies_audit_receipt)
        self.assertFalse(validated.calls_audit_service)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.calls_alert_service)
        self.assertFalse(validated.deletes_ciphertext)
        self.assertFalse(validated.mutates_attempt_state)
        self.assertFalse(validated.schedules_job)
        self.assertFalse(validated.authorizes_submission)


class SubmissionReconciliationValidationTests(SimpleTestCase):
    def test_timing_profile_rejects_drift(self) -> None:
        valid = expected_submission_reconciliation_profile_v1().timing
        self.assertEqual(
            validate_submission_reconciliation_timing_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scan_interval_max_ms=60_001),
            replace(valid, progress_deadline_ms=900_001),
            replace(valid, cleanup_retry_interval_max_ms=300_001),
            replace(valid, cleanup_alert_after_ms=899_999),
            replace(valid, scan_interval_max_ms=True),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionReconciliationDescriptorRejected):
                    validate_submission_reconciliation_timing_profile_v1(candidate)

    def test_state_profile_rejects_drift(self) -> None:
        valid = expected_submission_reconciliation_profile_v1().states
        self.assertEqual(
            validate_submission_reconciliation_state_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, candidate_states=valid.candidate_states[:-1]),
            replace(valid, candidate_states=tuple(reversed(valid.candidate_states))),
            replace(
                valid,
                candidate_states=valid.candidate_states
                + (SubmissionReconciliationCandidateState.READY,),
            ),
            replace(valid, terminal_outcomes=valid.terminal_outcomes[:-1]),
            replace(
                valid,
                terminal_outcomes=(
                    SubmissionReconciliationCandidateState.ABORTING,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionReconciliationDescriptorRejected):
                    validate_submission_reconciliation_state_profile_v1(candidate)

    def test_action_profile_rejects_drift(self) -> None:
        valid = expected_submission_reconciliation_profile_v1().actions
        self.assertEqual(
            validate_submission_reconciliation_action_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, actions=valid.actions[:-1]),
            replace(valid, actions=tuple(reversed(valid.actions))),
            replace(
                valid,
                actions=valid.actions
                + (SubmissionReconciliationAction.END_ABORTED,),
            ),
            replace(valid, persistent_cleanup_alert_type=AlertType.AUDIT_GAP_DETECTED),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionReconciliationDescriptorRejected):
                    validate_submission_reconciliation_action_profile_v1(candidate)

    def test_payload_profile_rejects_drift(self) -> None:
        valid = expected_submission_reconciliation_profile_v1().payload_policy
        self.assertEqual(
            validate_submission_reconciliation_payload_policy_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, allowed_fields=valid.allowed_fields[:-1]),
            replace(
                valid,
                allowed_fields=valid.allowed_fields
                + (SubmissionReconciliationAllowedPayloadField.SERVER_TIME,),
            ),
            replace(valid, forbidden_fields=valid.forbidden_fields[:-1]),
            SubmissionReconciliationPayloadPolicyV1(
                allowed_fields=(
                    SubmissionReconciliationForbiddenPayloadField.REPORT_TEXT,
                ),
                forbidden_fields=valid.forbidden_fields,
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionReconciliationDescriptorRejected):
                    validate_submission_reconciliation_payload_policy_v1(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_submission_reconciliation_profile_v1()
        self.assertEqual(
            validate_submission_reconciliation_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, timing=object()),
            replace(valid, states=object()),
            replace(valid, actions=object()),
            replace(valid, payload_policy=object()),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionReconciliationDescriptorRejected):
                    validate_submission_reconciliation_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        timing = expected_submission_reconciliation_profile_v1().timing
        with self.assertRaises(FrozenInstanceError):
            timing.scan_interval_max_ms = 1

        self.assertEqual(
            {field.name for field in fields(SubmissionReconciliationTimingProfileV1)},
            {
                "scan_interval_max_ms",
                "progress_deadline_ms",
                "cleanup_retry_interval_max_ms",
                "cleanup_alert_after_ms",
            },
        )
        self.assertEqual(
            {field.name for field in fields(SubmissionReconciliationProfileV1)},
            {"scheme_version", "timing", "states", "actions", "payload_policy"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_RECONCILIATION_SENTINEL"
        valid = expected_submission_reconciliation_profile_v1().timing
        with self.assertRaises(SubmissionReconciliationDescriptorRejected) as raised:
            validate_submission_reconciliation_timing_profile_v1(
                replace(valid, scan_interval_max_ms=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "submission_reconciliation_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
