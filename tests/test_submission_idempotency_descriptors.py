"""Negative tests for inert submission idempotency descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_IDEMPOTENCY_FORBIDDEN_CAPABILITIES_V1,
    SUBMISSION_IDEMPOTENCY_INVARIANTS_V1,
    SUBMISSION_IDEMPOTENCY_PROFILE_VERSION,
    SUBMISSION_IDEMPOTENCY_SCENARIOS_V1,
    StructurallyValidSubmissionIdempotencyProfileV1,
    SubmissionIdempotencyDescriptorRejected,
    SubmissionIdempotencyForbiddenCapability,
    SubmissionIdempotencyForbiddenCapabilityProfileV1,
    SubmissionIdempotencyInvariant,
    SubmissionIdempotencyInvariantProfileV1,
    SubmissionIdempotencyProfileV1,
    SubmissionIdempotencyScenario,
    SubmissionIdempotencyScenarioProfileV1,
    expected_submission_idempotency_profile_v1,
    validate_submission_idempotency_forbidden_capability_profile_v1,
    validate_submission_idempotency_invariant_profile_v1,
    validate_submission_idempotency_profile_v1,
    validate_submission_idempotency_scenario_profile_v1,
)


class SubmissionIdempotencyRegistryTests(SimpleTestCase):
    def test_version_scenarios_invariants_and_forbidden_capabilities_are_exact(
        self,
    ) -> None:
        self.assertEqual(SUBMISSION_IDEMPOTENCY_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_IDEMPOTENCY_SCENARIOS_V1),
            (
                "SEQUENTIAL_RETRY_EVERY_TRANSITION",
                "SYNCHRONIZED_PARALLEL_COPY_EVERY_TRANSITION",
                "MULTIPLE_APPLICATION_PROCESSES",
                "RECONCILIATION_AFTER_DUPLICATE_ARTIFACTS",
                "STALE_VERSION_AFTER_RECEIPT",
                "RESPONSE_LOSS_AFTER_SEALED",
                "CRASH_INJECTION_AT_NUMBERED_STEPS",
                "CLEANUP_AFTER_ABORT_OR_KEY_DESTRUCTION",
                "LOGGING_DURING_FAILURE",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_IDEMPOTENCY_INVARIANTS_V1),
            (
                "EXACTLY_ONE_ATTEMPT_OWNER",
                "AT_MOST_ONE_SEALED_REPORT_PER_ATTEMPT",
                "DATABASE_UNIQUENESS_AUTHORITATIVE_ACROSS_PROCESSES",
                "NO_DUPLICATE_REPORT_DEK_SURVIVES_RECONCILIATION",
                "NO_DUPLICATE_METADATA_ROW_SURVIVES_RECONCILIATION",
                "NO_DUPLICATE_CIPHERTEXT_OBJECT_SURVIVES_RECONCILIATION",
                "NO_DUPLICATE_ACCEPTANCE_EVENT_SURVIVES_RECONCILIATION",
                "STALE_VERSION_CANNOT_APPEND_USABLE_RECEIPT",
                "STALE_VERSION_CANNOT_COMMIT_SEALED",
                "RESPONSE_LOSS_CANNOT_AUTHORIZE_CREDENTIAL_REPLAY",
                "RESPONSE_LOSS_CANNOT_AUTHORIZE_SECOND_SUBMISSION",
                "CRASH_INJECTION_REACHES_ONLY_ALLOWED_STATE",
                "CLEANUP_CANNOT_RESURRECT_STAGED_CONTENT",
                "CLEANUP_CANNOT_DECRYPT_STAGED_CONTENT",
                "CLEANUP_CANNOT_EXPOSE_STAGED_CONTENT",
                "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_LOGS",
                "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_AUDIT",
                "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_ALERTS",
                "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_TRACING",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in SUBMISSION_IDEMPOTENCY_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "RUNS_PARALLEL_REQUESTS",
                "HANDLES_REQUEST",
                "INSPECTS_ATTEMPT_STATE",
                "LOCKS_DATABASE_ROW",
                "WRITES_STORAGE",
                "CREATES_REPORT_DEK",
                "APPENDS_AUDIT_EVENT",
                "RECONCILES_ARTIFACTS",
                "LOGS_REPORTER_INPUT",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_SUBMISSION",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_idempotency_profile_v1(
            expected_submission_idempotency_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidSubmissionIdempotencyProfileV1,
        )
        self.assertFalse(validated.runs_parallel_requests)
        self.assertFalse(validated.handles_request)
        self.assertFalse(validated.inspects_attempt_state)
        self.assertFalse(validated.locks_database_row)
        self.assertFalse(validated.writes_storage)
        self.assertFalse(validated.creates_report_dek)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.reconciles_artifacts)
        self.assertFalse(validated.logs_reporter_input)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_submission)
        for field_name in (
            "request",
            "credential",
            "report_text",
            "plaintext",
            "database_row",
            "lock",
            "thread",
            "response_body",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionIdempotencyValidationTests(SimpleTestCase):
    def test_scenario_profile_rejects_drift(self) -> None:
        valid = expected_submission_idempotency_profile_v1().scenarios
        self.assertEqual(
            validate_submission_idempotency_scenario_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scenarios=valid.scenarios[:-1]),
            replace(valid, scenarios=tuple(reversed(valid.scenarios))),
            replace(
                valid,
                scenarios=valid.scenarios
                + (SubmissionIdempotencyScenario.SEQUENTIAL_RETRY_EVERY_TRANSITION,),
            ),
            SubmissionIdempotencyScenarioProfileV1(
                scenarios=(
                    SubmissionIdempotencyInvariant.EXACTLY_ONE_ATTEMPT_OWNER,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionIdempotencyDescriptorRejected):
                    validate_submission_idempotency_scenario_profile_v1(
                        candidate
                    )

    def test_invariant_profile_rejects_drift(self) -> None:
        valid = expected_submission_idempotency_profile_v1().invariants
        self.assertEqual(
            validate_submission_idempotency_invariant_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, invariants=valid.invariants[:-1]),
            replace(valid, invariants=tuple(reversed(valid.invariants))),
            replace(
                valid,
                invariants=valid.invariants
                + (SubmissionIdempotencyInvariant.EXACTLY_ONE_ATTEMPT_OWNER,),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionIdempotencyDescriptorRejected):
                    validate_submission_idempotency_invariant_profile_v1(
                        candidate
                    )

    def test_forbidden_capability_profile_rejects_drift(self) -> None:
        valid = (
            expected_submission_idempotency_profile_v1().forbidden_capabilities
        )
        self.assertEqual(
            validate_submission_idempotency_forbidden_capability_profile_v1(
                valid
            ),
            valid,
        )
        for candidate in (
            object(),
            replace(
                valid,
                forbidden_capabilities=valid.forbidden_capabilities[:-1],
            ),
            replace(
                valid,
                forbidden_capabilities=tuple(
                    reversed(valid.forbidden_capabilities)
                ),
            ),
            SubmissionIdempotencyForbiddenCapabilityProfileV1(
                forbidden_capabilities=(
                    SubmissionIdempotencyScenario.LOGGING_DURING_FAILURE,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionIdempotencyDescriptorRejected):
                    validate_submission_idempotency_forbidden_capability_profile_v1(
                        candidate
                    )

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_submission_idempotency_profile_v1()
        self.assertEqual(
            validate_submission_idempotency_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(valid, scenarios=object()),
            replace(valid, invariants=object()),
            replace(valid, forbidden_capabilities=object()),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionIdempotencyDescriptorRejected):
                    validate_submission_idempotency_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_submission_idempotency_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(SubmissionIdempotencyProfileV1)},
            {
                "scheme_version",
                "scenarios",
                "invariants",
                "forbidden_capabilities",
            },
        )
        self.assertEqual(
            {
                field.name
                for field in fields(SubmissionIdempotencyInvariantProfileV1)
            },
            {"invariants"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_IDEMPOTENCY_SENTINEL"
        valid = expected_submission_idempotency_profile_v1()
        with self.assertRaises(SubmissionIdempotencyDescriptorRejected) as raised:
            validate_submission_idempotency_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "submission_idempotency_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
