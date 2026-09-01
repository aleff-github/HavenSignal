"""Negative tests for inert submission failure descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_FAILURE_BOUNDARIES_V1,
    SUBMISSION_FAILURE_CASES_V1,
    SUBMISSION_FAILURE_PROFILE_VERSION,
    SUBMISSION_FAILURE_REQUIRED_RESULTS_V1,
    StructurallyValidSubmissionFailureProfileV1,
    SubmissionFailureBoundary,
    SubmissionFailureCaseV1,
    SubmissionFailureDescriptorRejected,
    SubmissionFailureProfileV1,
    SubmissionFailureRequiredResult,
    expected_submission_failure_profile_v1,
    validate_submission_failure_case_v1,
    validate_submission_failure_profile_v1,
)


class SubmissionFailureRegistryTests(SimpleTestCase):
    def test_version_boundaries_and_results_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_FAILURE_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_FAILURE_BOUNDARIES_V1),
            (
                "UNSUPPORTED_METHOD_FRAMING_SIZE_CSRF_CAPTCHA_OR_ATTEMPT",
                "PARALLEL_REQUESTS_FOR_ONE_ATTEMPT",
                "AUDIT_REQUESTED_UNAVAILABLE",
                "VALIDATION_OR_SANDBOX_UNCERTAINTY",
                "KEY_SERVICE_UNAVAILABLE",
                "ENCRYPTION_OR_STAGING_FAILURE",
                "METADATA_TRANSACTION_FAILURE",
                "SUBMISSION_RECEIVED_AUDIT_UNAVAILABLE",
                "CRASH_AFTER_FINAL_RECEIPT_BEFORE_SEALED",
                "CRASH_AFTER_SEALED_BEFORE_OR_DURING_RESPONSE",
                "DUPLICATE_OR_STALE_RETRY_AFTER_ACCEPTANCE",
                "KEY_OR_CIPHERTEXT_CLEANUP_FAILURE",
                "UNKNOWN_STATE_VERSION_OR_RECEIPT",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_FAILURE_REQUIRED_RESULTS_V1),
            (
                "REJECT_BEFORE_ACCEPTANCE_NO_FALLBACK_OR_THIRD_PARTY_CHALLENGE",
                "ONE_DATABASE_WINNER_LOSERS_NO_PIPELINE",
                "NO_KEY_OR_DURABLE_REPORT_CONTENT_CREATED",
                "REJECT_NO_WEAKER_PARSER_OR_IN_PROCESS_FALLBACK",
                "NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS",
                "NON_VISIBLE_DESTROY_SCOPED_KEY_AND_STAGED_OBJECTS",
                "NO_SEALED_RECONCILE_OR_DESTROY_STAGED_MATERIAL",
                "NON_VISIBLE_STAGING_APPROVED_RECONCILIATION_NO_CREDENTIALS",
                "RECONCILER_FINISH_ONLY_WITH_EXACT_BINDINGS",
                "ONE_ACCEPTED_REPORT_NO_REISSUE_NO_DUPLICATE",
                "CONTROLLED_INDETERMINATE_NO_STATUS_ORACLE_NO_REDISPLAY",
                "INACCESSIBLE_RETRY_AND_ALERT_APPROVED_POLICY",
                "FAIL_CLOSED_SECURITY_REVIEW_NO_GUESSED_TRANSITION",
            ),
        )

    def test_failure_cases_are_exact_content_free_and_fail_closed(self) -> None:
        self.assertEqual(len(SUBMISSION_FAILURE_CASES_V1), 13)
        self.assertEqual(
            tuple(item.boundary for item in SUBMISSION_FAILURE_CASES_V1),
            SUBMISSION_FAILURE_BOUNDARIES_V1,
        )
        self.assertEqual(
            tuple(item.required_result for item in SUBMISSION_FAILURE_CASES_V1),
            SUBMISSION_FAILURE_REQUIRED_RESULTS_V1,
        )
        self.assertTrue(all(item.content_free for item in SUBMISSION_FAILURE_CASES_V1))
        self.assertTrue(all(item.fail_closed for item in SUBMISSION_FAILURE_CASES_V1))

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_failure_profile_v1(
            expected_submission_failure_profile_v1()
        )
        self.assertIsInstance(validated, StructurallyValidSubmissionFailureProfileV1)
        self.assertFalse(validated.handles_request)
        self.assertFalse(validated.starts_pipeline)
        self.assertFalse(validated.calls_service)
        self.assertFalse(validated.writes_storage)
        self.assertFalse(validated.creates_key)
        self.assertFalse(validated.persists_plaintext)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.mutates_state)
        self.assertFalse(validated.returns_credentials)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_submission)
        for field_name in (
            "request",
            "credential",
            "receipt",
            "report_text",
            "plaintext",
            "database_row",
            "response_body",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionFailureValidationTests(SimpleTestCase):
    def test_failure_case_rejects_drift(self) -> None:
        valid = SUBMISSION_FAILURE_CASES_V1[0]
        self.assertEqual(validate_submission_failure_case_v1(valid), valid)
        for candidate in (
            object(),
            replace(
                valid,
                boundary=SubmissionFailureBoundary.KEY_SERVICE_UNAVAILABLE,
            ),
            replace(
                valid,
                required_result=(
                    SubmissionFailureRequiredResult.
                    NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS
                ),
            ),
            replace(valid, content_free=False),
            replace(valid, fail_closed=False),
            SubmissionFailureCaseV1(
                boundary=SubmissionFailureBoundary.AUDIT_REQUESTED_UNAVAILABLE,
                required_result=(
                    SubmissionFailureRequiredResult.
                    ONE_DATABASE_WINNER_LOSERS_NO_PIPELINE
                ),
                content_free=True,
                fail_closed=True,
            ),
            SubmissionFailureCaseV1(
                boundary=SubmissionFailureRequiredResult.
                NO_KEY_OR_DURABLE_REPORT_CONTENT_CREATED,
                required_result=(
                    SubmissionFailureRequiredResult.
                    NO_KEY_OR_DURABLE_REPORT_CONTENT_CREATED
                ),
                content_free=True,
                fail_closed=True,
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionFailureDescriptorRejected):
                    validate_submission_failure_case_v1(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_submission_failure_profile_v1()
        self.assertEqual(
            validate_submission_failure_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(valid, cases=valid.cases[:-1]),
            replace(valid, cases=tuple(reversed(valid.cases))),
            replace(
                valid,
                cases=valid.cases + (SUBMISSION_FAILURE_CASES_V1[0],),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionFailureDescriptorRejected):
                    validate_submission_failure_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_submission_failure_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(SubmissionFailureProfileV1)},
            {"scheme_version", "cases"},
        )
        self.assertEqual(
            {field.name for field in fields(SubmissionFailureCaseV1)},
            {"boundary", "required_result", "content_free", "fail_closed"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_FAILURE_SENTINEL"
        valid = expected_submission_failure_profile_v1()
        with self.assertRaises(SubmissionFailureDescriptorRejected) as raised:
            validate_submission_failure_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(str(raised.exception), "submission_failure_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
