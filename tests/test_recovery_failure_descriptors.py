"""Negative tests for inert recovery failure descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_FAILURE_BOUNDARIES_V1,
    RECOVERY_FAILURE_CASES_V1,
    RECOVERY_FAILURE_FORBIDDEN_CAPABILITIES_V1,
    RECOVERY_FAILURE_PROFILE_VERSION,
    RECOVERY_FAILURE_REQUIRED_RESULTS_V1,
    RecoveryFailureBoundary,
    RecoveryFailureCaseV1,
    RecoveryFailureDescriptorRejected,
    RecoveryFailureForbiddenCapability,
    RecoveryFailureProfileV1,
    RecoveryFailureRequiredResult,
    StructurallyValidRecoveryFailureProfileV1,
    expected_recovery_failure_profile_v1,
    validate_recovery_failure_case_v1,
    validate_recovery_failure_profile_v1,
)


class RecoveryFailureRegistryTests(SimpleTestCase):
    def test_version_boundaries_results_and_forbidden_capabilities_are_exact(
        self,
    ) -> None:
        self.assertEqual(RECOVERY_FAILURE_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_FAILURE_BOUNDARIES_V1),
            (
                "RANDOM_SOURCE_UNAVAILABLE_OR_WRONG_LENGTH",
                "REPEATED_TICKET_ID_COLLISION",
                "ENCODING_MALFORMED_OR_NON_CANONICAL",
                "VERIFIER_SERVICE_OR_KEY_UNAVAILABLE",
                "UNKNOWN_VERSION_OR_KEY_IDENTIFIER",
                "HMAC_MISMATCH",
                "CORRECT_CREDENTIALS_BUT_RESPONSE_UNAVAILABLE_EXPIRED_OR_DESTROYED",
                "CONCURRENT_FIRST_READS",
                "RESPONSE_DEK_EXPIRED",
                "LOGGING_OR_TELEMETRY_ATTEMPTS_TO_INCLUDE_CREDENTIALS",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_FAILURE_REQUIRED_RESULTS_V1),
            (
                "ABORT_BEFORE_ACCEPTANCE_NO_FALLBACK_GENERATOR",
                "ABORT_AFTER_THREE_FRESH_ID_ATTEMPTS_WITHOUT_ID_DISCLOSURE",
                "GENERIC_NON_SUCCESS_NO_LOOKUP_OR_ALTERNATE_DECODER",
                "GENERIC_NON_SUCCESS_NO_LOCAL_UNKEYED_OR_PLAINTEXT_FALLBACK",
                "GENERIC_NON_SUCCESS_AND_CONTROLLED_INTERNAL_EVENT",
                "GENERIC_NON_SUCCESS_NO_PARTIAL_MATCH_DETAIL",
                "SAME_GENERIC_NON_SUCCESS",
                "EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT_AND_EXPIRY",
                "DENY_BEFORE_USE_WHILE_CLEANUP_RETRIES",
                "REJECT_OR_REDACT_AT_SCHEMA_BOUNDARY_AND_FAIL_SECURITY_TEST",
            ),
        )
        self.assertEqual(
            tuple(
                item.value for item in RECOVERY_FAILURE_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "GENERATES_RANDOMNESS",
                "RETRIES_TICKET_ID_CREATION",
                "DECODES_CREDENTIAL",
                "CALLS_VERIFIER_SERVICE",
                "COMPARES_HMAC_TAG",
                "READS_RESPONSE_STATE",
                "CALLS_KEY_SERVICE",
                "MUTATES_FIRST_READ",
                "LOGS_CREDENTIAL",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_RECOVERY",
            ),
        )

    def test_failure_cases_are_exact_generic_and_fail_closed(self) -> None:
        self.assertEqual(len(RECOVERY_FAILURE_CASES_V1), 10)
        self.assertEqual(
            tuple(item.boundary for item in RECOVERY_FAILURE_CASES_V1),
            RECOVERY_FAILURE_BOUNDARIES_V1,
        )
        self.assertEqual(
            tuple(item.required_result for item in RECOVERY_FAILURE_CASES_V1),
            RECOVERY_FAILURE_REQUIRED_RESULTS_V1,
        )
        self.assertTrue(
            all(item.generic_external_result for item in RECOVERY_FAILURE_CASES_V1)
        )
        self.assertTrue(all(item.fail_closed for item in RECOVERY_FAILURE_CASES_V1))

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_failure_profile_v1(
            expected_recovery_failure_profile_v1()
        )
        self.assertIsInstance(validated, StructurallyValidRecoveryFailureProfileV1)
        self.assertFalse(validated.generates_randomness)
        self.assertFalse(validated.decodes_credential)
        self.assertFalse(validated.calls_verifier_service)
        self.assertFalse(validated.compares_hmac_tag)
        self.assertFalse(validated.reads_response_state)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.mutates_first_read)
        self.assertFalse(validated.logs_credential)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "verifier_tag",
            "verifier_key",
            "response_note",
            "response_dek",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryFailureValidationTests(SimpleTestCase):
    def test_failure_case_rejects_drift(self) -> None:
        valid = RECOVERY_FAILURE_CASES_V1[0]
        self.assertEqual(validate_recovery_failure_case_v1(valid), valid)
        for candidate in (
            object(),
            replace(
                valid,
                boundary=RecoveryFailureBoundary.HMAC_MISMATCH,
            ),
            replace(
                valid,
                required_result=(
                    RecoveryFailureRequiredResult.
                    GENERIC_NON_SUCCESS_NO_PARTIAL_MATCH_DETAIL
                ),
            ),
            replace(valid, generic_external_result=False),
            replace(valid, fail_closed=False),
            RecoveryFailureCaseV1(
                boundary=RecoveryFailureBoundary.HMAC_MISMATCH,
                required_result=(
                    RecoveryFailureRequiredResult.
                    GENERIC_NON_SUCCESS_NO_LOOKUP_OR_ALTERNATE_DECODER
                ),
                generic_external_result=True,
                fail_closed=True,
            ),
            RecoveryFailureCaseV1(
                boundary=RecoveryFailureRequiredResult.SAME_GENERIC_NON_SUCCESS,
                required_result=RecoveryFailureRequiredResult.SAME_GENERIC_NON_SUCCESS,
                generic_external_result=True,
                fail_closed=True,
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryFailureDescriptorRejected):
                    validate_recovery_failure_case_v1(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_failure_profile_v1()
        self.assertEqual(
            validate_recovery_failure_profile_v1(valid).profile,
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
                forbidden_capabilities=valid.forbidden_capabilities[:-1],
            ),
            replace(
                valid,
                forbidden_capabilities=tuple(
                    reversed(valid.forbidden_capabilities)
                ),
            ),
            replace(
                valid,
                forbidden_capabilities=(
                    RecoveryFailureForbiddenCapability.EXPOSES_ENDPOINT,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryFailureDescriptorRejected):
                    validate_recovery_failure_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_recovery_failure_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(RecoveryFailureProfileV1)},
            {"scheme_version", "cases", "forbidden_capabilities"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryFailureCaseV1)},
            {
                "boundary",
                "required_result",
                "generic_external_result",
                "fail_closed",
            },
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RECOVERY_FAILURE_SENTINEL"
        valid = expected_recovery_failure_profile_v1()
        with self.assertRaises(RecoveryFailureDescriptorRejected) as raised:
            validate_recovery_failure_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(str(raised.exception), "recovery_failure_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
