"""Negative tests for inert recovery verification descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_VERIFICATION_ALGORITHMS_V1,
    RECOVERY_VERIFICATION_COMPARISONS_V1,
    RECOVERY_VERIFICATION_FORBIDDEN_CAPABILITIES_V1,
    RECOVERY_VERIFICATION_INPUT_REQUIREMENTS_V1,
    RECOVERY_VERIFICATION_PROFILE_VERSION,
    RECOVERY_VERIFICATION_RESULT_RULES_V1,
    RECOVERY_VERIFICATION_TAG_BYTES,
    RECOVERY_VERIFICATION_UNIFORMITY_REQUIREMENTS_V1,
    RecoveryVerificationAlgorithm,
    RecoveryVerificationAlgorithmProfileV1,
    RecoveryVerificationCapabilityDenialProfileV1,
    RecoveryVerificationComparison,
    RecoveryVerificationDescriptorRejected,
    RecoveryVerificationForbiddenCapability,
    RecoveryVerificationInputProfileV1,
    RecoveryVerificationInputRequirement,
    RecoveryVerificationProfileV1,
    RecoveryVerificationResultRule,
    RecoveryVerificationUniformityProfileV1,
    RecoveryVerificationUniformityRequirement,
    StructurallyValidRecoveryVerificationProfileV1,
    expected_recovery_verification_algorithm_profile_v1,
    expected_recovery_verification_capability_denial_profile_v1,
    expected_recovery_verification_input_profile_v1,
    expected_recovery_verification_profile_v1,
    expected_recovery_verification_uniformity_profile_v1,
    validate_recovery_verification_algorithm_profile_v1,
    validate_recovery_verification_capability_denial_profile_v1,
    validate_recovery_verification_input_profile_v1,
    validate_recovery_verification_profile_v1,
    validate_recovery_verification_uniformity_profile_v1,
)


class RecoveryVerificationRegistryTests(SimpleTestCase):
    def test_version_algorithm_comparison_results_inputs_and_uniformity_are_exact(
        self,
    ) -> None:
        self.assertEqual(RECOVERY_VERIFICATION_PROFILE_VERSION, 1)
        self.assertEqual(RECOVERY_VERIFICATION_TAG_BYTES, 32)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFICATION_ALGORITHMS_V1),
            ("HMAC_SHA256_FULL_LENGTH",),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFICATION_COMPARISONS_V1),
            ("CONSTANT_TIME_FULL_TAG",),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFICATION_RESULT_RULES_V1),
            (
                "BOOLEAN_ONLY",
                "HMAC_SUCCESS_NECESSARY_NOT_SUFFICIENT",
            ),
        )
        self.assertEqual(
            tuple(
                item.value for item in RECOVERY_VERIFICATION_INPUT_REQUIREMENTS_V1
            ),
            (
                "CANONICAL_TICKET_ID",
                "CANONICAL_RECOVERY_SECRET",
                "STORED_SCHEME_VERSION",
                "SERVER_SELECTED_KEY_ID",
                "STORED_FULL_LENGTH_TAG",
                "DUMMY_RECORD_FOR_UNKNOWN_TICKET",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_VERIFICATION_UNIFORMITY_REQUIREMENTS_V1
            ),
            (
                "GENERIC_EXTERNAL_NON_SUCCESS",
                "UNKNOWN_TICKET_DUMMY_VERIFICATION",
                "SAME_STATUS_TEMPLATE_HEADERS_RESPONSE_CLASS_AND_WORDING",
                "TIMING_DISTRIBUTION_TEST_REQUIRED",
                "NO_PERFECT_INDISTINGUISHABILITY_CLAIM",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_VERIFICATION_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "COMPUTES_HMAC",
                "COMPARES_TAGS",
                "EXECUTES_DUMMY_VERIFICATION",
                "RETURNS_EXPECTED_TAG",
                "RETURNS_PARTIAL_MATCH_DETAIL",
                "READS_RESPONSE_STATE",
                "VALIDATES_CAPTCHA",
                "CALLS_KEY_SERVICE",
                "AUTHORIZES_RESPONSE_DEK_USE",
                "LOGS_CREDENTIAL",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_RECOVERY",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_verification_profile_v1(
            expected_recovery_verification_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryVerificationProfileV1,
        )
        self.assertFalse(validated.computes_hmac)
        self.assertFalse(validated.compares_tags)
        self.assertFalse(validated.executes_dummy_verification)
        self.assertFalse(validated.returns_expected_tag)
        self.assertFalse(validated.returns_partial_match_detail)
        self.assertFalse(validated.reads_response_state)
        self.assertFalse(validated.validates_captcha)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.authorizes_response_dek_use)
        self.assertFalse(validated.logs_credential)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "verifier_tag",
            "expected_tag",
            "partial_match",
            "response_note",
            "response_dek",
            "captcha",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryVerificationValidationTests(SimpleTestCase):
    def test_component_profiles_accept_only_reviewed_metadata(self) -> None:
        self.assertEqual(
            validate_recovery_verification_algorithm_profile_v1(
                expected_recovery_verification_algorithm_profile_v1()
            ),
            expected_recovery_verification_algorithm_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verification_input_profile_v1(
                expected_recovery_verification_input_profile_v1()
            ),
            expected_recovery_verification_input_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verification_uniformity_profile_v1(
                expected_recovery_verification_uniformity_profile_v1()
            ),
            expected_recovery_verification_uniformity_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verification_capability_denial_profile_v1(
                expected_recovery_verification_capability_denial_profile_v1()
            ),
            expected_recovery_verification_capability_denial_profile_v1(),
        )

    def test_component_profiles_reject_drift(self) -> None:
        invalid_cases = (
            (
                validate_recovery_verification_algorithm_profile_v1,
                RecoveryVerificationAlgorithmProfileV1(
                    algorithms=(),
                    tag_size_bytes=RECOVERY_VERIFICATION_TAG_BYTES,
                    comparisons=RECOVERY_VERIFICATION_COMPARISONS_V1,
                    result_rules=RECOVERY_VERIFICATION_RESULT_RULES_V1,
                ),
            ),
            (
                validate_recovery_verification_algorithm_profile_v1,
                RecoveryVerificationAlgorithmProfileV1(
                    algorithms=RECOVERY_VERIFICATION_ALGORITHMS_V1,
                    tag_size_bytes=True,
                    comparisons=RECOVERY_VERIFICATION_COMPARISONS_V1,
                    result_rules=RECOVERY_VERIFICATION_RESULT_RULES_V1,
                ),
            ),
            (
                validate_recovery_verification_algorithm_profile_v1,
                RecoveryVerificationAlgorithmProfileV1(
                    algorithms=RECOVERY_VERIFICATION_ALGORITHMS_V1,
                    tag_size_bytes=16,
                    comparisons=RECOVERY_VERIFICATION_COMPARISONS_V1,
                    result_rules=RECOVERY_VERIFICATION_RESULT_RULES_V1,
                ),
            ),
            (
                validate_recovery_verification_algorithm_profile_v1,
                RecoveryVerificationAlgorithmProfileV1(
                    algorithms=RECOVERY_VERIFICATION_ALGORITHMS_V1,
                    tag_size_bytes=RECOVERY_VERIFICATION_TAG_BYTES,
                    comparisons=(),
                    result_rules=RECOVERY_VERIFICATION_RESULT_RULES_V1,
                ),
            ),
            (
                validate_recovery_verification_input_profile_v1,
                RecoveryVerificationInputProfileV1(
                    requirements=(
                        RecoveryVerificationInputRequirement.
                        CANONICAL_RECOVERY_SECRET,
                    )
                ),
            ),
            (
                validate_recovery_verification_uniformity_profile_v1,
                RecoveryVerificationUniformityProfileV1(
                    requirements=(
                        RecoveryVerificationUniformityRequirement.
                        GENERIC_EXTERNAL_NON_SUCCESS,
                    )
                ),
            ),
            (
                validate_recovery_verification_capability_denial_profile_v1,
                RecoveryVerificationCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryVerificationForbiddenCapability.COMPUTES_HMAC,
                    )
                ),
            ),
        )
        for validator, candidate in invalid_cases:
            with self.subTest(validator=validator.__name__, candidate=candidate):
                with self.assertRaises(RecoveryVerificationDescriptorRejected):
                    validator(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_verification_profile_v1()
        self.assertEqual(
            validate_recovery_verification_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(
                valid,
                algorithm=RecoveryVerificationAlgorithmProfileV1(
                    algorithms=(
                        RecoveryVerificationAlgorithm.HMAC_SHA256_FULL_LENGTH,
                    ),
                    tag_size_bytes=RECOVERY_VERIFICATION_TAG_BYTES,
                    comparisons=(
                        RecoveryVerificationComparison.CONSTANT_TIME_FULL_TAG,
                    ),
                    result_rules=(
                        RecoveryVerificationResultRule.BOOLEAN_ONLY,
                    ),
                ),
            ),
            replace(
                valid,
                inputs=RecoveryVerificationInputProfileV1(
                    requirements=RECOVERY_VERIFICATION_INPUT_REQUIREMENTS_V1[:-1]
                ),
            ),
            replace(
                valid,
                uniformity=RecoveryVerificationUniformityProfileV1(
                    requirements=tuple(
                        reversed(RECOVERY_VERIFICATION_UNIFORMITY_REQUIREMENTS_V1)
                    )
                ),
            ),
            replace(
                valid,
                capability_denials=RecoveryVerificationCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryVerificationForbiddenCapability.
                        AUTHORIZES_RECOVERY,
                    )
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryVerificationDescriptorRejected):
                    validate_recovery_verification_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_recovery_verification_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(RecoveryVerificationProfileV1)},
            {
                "scheme_version",
                "algorithm",
                "inputs",
                "uniformity",
                "capability_denials",
            },
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerificationAlgorithmProfileV1)},
            {"algorithms", "tag_size_bytes", "comparisons", "result_rules"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerificationInputProfileV1)},
            {"requirements"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerificationUniformityProfileV1)},
            {"requirements"},
        )
        self.assertEqual(
            {
                field.name
                for field in fields(RecoveryVerificationCapabilityDenialProfileV1)
            },
            {"forbidden_capabilities"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RECOVERY_VERIFICATION_SENTINEL"
        valid = expected_recovery_verification_profile_v1()
        with self.assertRaises(RecoveryVerificationDescriptorRejected) as raised:
            validate_recovery_verification_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "recovery_verification_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
