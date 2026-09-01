"""Negative tests for inert submission retry descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_RETRY_FORBIDDEN_SIGNALS_V1,
    SUBMISSION_RETRY_PROFILE_VERSION,
    SUBMISSION_RETRY_REQUIRED_OUTCOMES_V1,
    SUBMISSION_RETRY_SOURCES_V1,
    StructurallyValidSubmissionRetryProfileV1,
    SubmissionRetryDescriptorRejected,
    SubmissionRetryForbiddenSignal,
    SubmissionRetryOutcomeProfileV1,
    SubmissionRetryProfileV1,
    SubmissionRetryRequiredOutcome,
    SubmissionRetrySignalPolicyV1,
    SubmissionRetrySource,
    SubmissionRetrySourceProfileV1,
    expected_submission_retry_profile_v1,
    validate_submission_retry_outcome_profile_v1,
    validate_submission_retry_profile_v1,
    validate_submission_retry_signal_policy_v1,
    validate_submission_retry_source_profile_v1,
)


class SubmissionRetryRegistryTests(SimpleTestCase):
    def test_version_sources_outcomes_and_signal_denials_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_RETRY_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_RETRY_SOURCES_V1),
            (
                "PARALLEL_COPY",
                "DELAYED_REQUEST",
                "PROXY_RETRY",
                "BROWSER_RETRY",
                "STALE_TAB",
                "POST_ACCEPTANCE_RETRY",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_RETRY_REQUIRED_OUTCOMES_V1),
            (
                "ONE_DATABASE_WINNER",
                "LOSERS_START_NO_PIPELINE",
                "NO_SECOND_REPORT",
                "NO_SECOND_REPORT_DEK",
                "NO_DUPLICATE_ACCEPTANCE_EVENT",
                "NO_CREDENTIAL_REDISPLAY",
                "CONTROLLED_INDETERMINATE_RESPONSE",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_RETRY_FORBIDDEN_SIGNALS_V1),
            (
                "REPORT_CONTENT",
                "RECOVERY_SECRET",
                "TICKET_ID",
                "ORIGINAL_FILENAME",
                "REQUEST_HEADER",
                "IP_ADDRESS",
                "USER_AGENT",
                "STATUS_ORACLE",
                "RAW_ERROR",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_retry_profile_v1(
            expected_submission_retry_profile_v1()
        )
        self.assertIsInstance(validated, StructurallyValidSubmissionRetryProfileV1)
        self.assertFalse(validated.parses_request)
        self.assertFalse(validated.verifies_attempt_credential)
        self.assertFalse(validated.claims_attempt)
        self.assertFalse(validated.inspects_database_state)
        self.assertFalse(validated.creates_report)
        self.assertFalse(validated.creates_report_dek)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.redisplays_credentials)
        self.assertFalse(validated.exposes_status_oracle)
        self.assertFalse(validated.calls_service)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_submission)
        for field_name in (
            "request",
            "credential",
            "ticket_id",
            "recovery_secret",
            "report_text",
            "database_row",
            "response_body",
            "status",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionRetryValidationTests(SimpleTestCase):
    def test_source_profile_rejects_drift(self) -> None:
        valid = expected_submission_retry_profile_v1().sources
        self.assertEqual(validate_submission_retry_source_profile_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, sources=valid.sources[:-1]),
            replace(valid, sources=tuple(reversed(valid.sources))),
            replace(
                valid,
                sources=valid.sources + (SubmissionRetrySource.PARALLEL_COPY,),
            ),
            SubmissionRetrySourceProfileV1(
                sources=(SubmissionRetryRequiredOutcome.NO_SECOND_REPORT,),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionRetryDescriptorRejected):
                    validate_submission_retry_source_profile_v1(candidate)

    def test_outcome_profile_rejects_drift(self) -> None:
        valid = expected_submission_retry_profile_v1().outcomes
        self.assertEqual(validate_submission_retry_outcome_profile_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, required_outcomes=valid.required_outcomes[:-1]),
            replace(
                valid,
                required_outcomes=tuple(reversed(valid.required_outcomes)),
            ),
            replace(
                valid,
                required_outcomes=valid.required_outcomes
                + (SubmissionRetryRequiredOutcome.NO_SECOND_REPORT,),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionRetryDescriptorRejected):
                    validate_submission_retry_outcome_profile_v1(candidate)

    def test_signal_policy_rejects_drift(self) -> None:
        valid = expected_submission_retry_profile_v1().signal_policy
        self.assertEqual(validate_submission_retry_signal_policy_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, forbidden_signals=valid.forbidden_signals[:-1]),
            replace(
                valid,
                forbidden_signals=tuple(reversed(valid.forbidden_signals)),
            ),
            SubmissionRetrySignalPolicyV1(
                forbidden_signals=(SubmissionRetrySource.STALE_TAB,),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionRetryDescriptorRejected):
                    validate_submission_retry_signal_policy_v1(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_submission_retry_profile_v1()
        self.assertEqual(validate_submission_retry_profile_v1(valid).profile, valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(valid, sources=object()),
            replace(valid, outcomes=object()),
            replace(valid, signal_policy=object()),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SubmissionRetryDescriptorRejected):
                    validate_submission_retry_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_submission_retry_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(SubmissionRetryProfileV1)},
            {"scheme_version", "sources", "outcomes", "signal_policy"},
        )
        self.assertEqual(
            {field.name for field in fields(SubmissionRetryOutcomeProfileV1)},
            {"required_outcomes"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_RETRY_SENTINEL"
        valid = expected_submission_retry_profile_v1()
        with self.assertRaises(SubmissionRetryDescriptorRejected) as raised:
            validate_submission_retry_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(str(raised.exception), "submission_retry_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
