"""Negative tests for inert recovery eligibility descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_ELIGIBILITY_FORBIDDEN_CAPABILITIES_V1,
    RECOVERY_ELIGIBILITY_PROFILE_VERSION,
    RECOVERY_ELIGIBILITY_REQUIREMENTS_V1,
    RECOVERY_ELIGIBILITY_STATES_V1,
    RECOVERY_FIRST_READ_EXPIRY_SECONDS,
    RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS,
    RecoveryEligibilityCapabilityDenialProfileV1,
    RecoveryEligibilityDescriptorRejected,
    RecoveryEligibilityForbiddenCapability,
    RecoveryEligibilityProfileV1,
    RecoveryEligibilityRequirement,
    RecoveryEligibilityRequirementProfileV1,
    RecoveryEligibilityState,
    RecoveryEligibilityStateProfileV1,
    RecoveryEligibilityTimingProfileV1,
    StructurallyValidRecoveryEligibilityProfileV1,
    expected_recovery_eligibility_capability_denial_profile_v1,
    expected_recovery_eligibility_profile_v1,
    expected_recovery_eligibility_requirement_profile_v1,
    expected_recovery_eligibility_state_profile_v1,
    expected_recovery_eligibility_timing_profile_v1,
    validate_recovery_eligibility_capability_denial_profile_v1,
    validate_recovery_eligibility_profile_v1,
    validate_recovery_eligibility_requirement_profile_v1,
    validate_recovery_eligibility_state_profile_v1,
    validate_recovery_eligibility_timing_profile_v1,
)


class RecoveryEligibilityRegistryTests(SimpleTestCase):
    def test_version_states_requirements_timing_and_denials_are_exact(self) -> None:
        self.assertEqual(RECOVERY_ELIGIBILITY_PROFILE_VERSION, 1)
        self.assertEqual(RECOVERY_FIRST_READ_EXPIRY_SECONDS, 259200)
        self.assertEqual(RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS, 7776000)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_ELIGIBILITY_STATES_V1),
            (
                "RESPONSE_UNAVAILABLE",
                "RESPONSE_AVAILABLE_UNREAD",
                "READ_WINDOW_OPEN",
                "READ_WINDOW_EXPIRED",
                "NEVER_READ_EXPIRED",
                "RESPONSE_DESTROYED",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_ELIGIBILITY_REQUIREMENTS_V1),
            (
                "POST_CREDENTIALS_AND_CAPTCHA_REQUIRED",
                "SERVER_AUTHORITATIVE_STATE",
                "VERIFIER_SUCCESS_NOT_SUFFICIENT",
                "RESPONSE_DEK_AUTHORIZATION_REQUIRED",
                "ORIGINAL_REPORT_KEY_DESTROYED_BEFORE_VISIBLE",
                "UNREAD_EXPIRY_FIXED_AT_RESPONSE_AVAILABLE",
                "EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT",
                "FIRST_READ_EXPIRY_NON_EXTENDING",
                "DENY_AFTER_SERVER_AUTHORITATIVE_EXPIRY",
                "INVALIDATE_RECOVERY_STATE_AT_EXPIRY",
                "GENERIC_NON_SUCCESS_FOR_INELIGIBLE_STATE",
            ),
        )
        self.assertEqual(
            tuple(
                item.value for item in RECOVERY_ELIGIBILITY_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "PERFORMS_LOOKUP",
                "VALIDATES_CREDENTIALS",
                "VALIDATES_CAPTCHA",
                "CALLS_VERIFIER_SERVICE",
                "CALLS_KEY_SERVICE",
                "READS_RESPONSE_STATE",
                "READS_RESPONSE_CIPHERTEXT",
                "DECRYPTS_RESPONSE",
                "MUTATES_FIRST_READ",
                "DESTROYS_RESPONSE_DEK",
                "INVALIDATES_RECOVERY_STATE",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_RECOVERY",
                "EXTENDS_RESPONSE_WINDOW",
                "LOGS_CREDENTIALS",
                "RETURNS_DISTINCT_FAILURE",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_eligibility_profile_v1(
            expected_recovery_eligibility_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryEligibilityProfileV1,
        )
        self.assertFalse(validated.performs_lookup)
        self.assertFalse(validated.validates_credentials)
        self.assertFalse(validated.validates_captcha)
        self.assertFalse(validated.calls_verifier_service)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.reads_response_state)
        self.assertFalse(validated.reads_response_ciphertext)
        self.assertFalse(validated.decrypts_response)
        self.assertFalse(validated.mutates_first_read)
        self.assertFalse(validated.destroys_response_dek)
        self.assertFalse(validated.invalidates_recovery_state)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        self.assertFalse(validated.extends_response_window)
        self.assertFalse(validated.logs_credentials)
        self.assertFalse(validated.returns_distinct_failure)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "captcha_answer",
            "verifier_result",
            "response_dek",
            "plaintext",
            "endpoint",
            "first_read_at",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryEligibilityValidationTests(SimpleTestCase):
    def test_component_profiles_accept_only_reviewed_metadata(self) -> None:
        self.assertEqual(
            validate_recovery_eligibility_state_profile_v1(
                expected_recovery_eligibility_state_profile_v1()
            ),
            expected_recovery_eligibility_state_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_eligibility_timing_profile_v1(
                expected_recovery_eligibility_timing_profile_v1()
            ),
            expected_recovery_eligibility_timing_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_eligibility_requirement_profile_v1(
                expected_recovery_eligibility_requirement_profile_v1()
            ),
            expected_recovery_eligibility_requirement_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_eligibility_capability_denial_profile_v1(
                expected_recovery_eligibility_capability_denial_profile_v1()
            ),
            expected_recovery_eligibility_capability_denial_profile_v1(),
        )

    def test_component_profiles_reject_drift(self) -> None:
        invalid_cases = (
            (
                validate_recovery_eligibility_state_profile_v1,
                RecoveryEligibilityStateProfileV1(
                    states=RECOVERY_ELIGIBILITY_STATES_V1[:-1]
                ),
            ),
            (
                validate_recovery_eligibility_timing_profile_v1,
                RecoveryEligibilityTimingProfileV1(
                    first_read_expiry_seconds=RECOVERY_FIRST_READ_EXPIRY_SECONDS,
                    unread_response_expiry_seconds=90,
                ),
            ),
            (
                validate_recovery_eligibility_requirement_profile_v1,
                RecoveryEligibilityRequirementProfileV1(
                    requirements=(
                        RecoveryEligibilityRequirement.SERVER_AUTHORITATIVE_STATE,
                    )
                ),
            ),
            (
                validate_recovery_eligibility_capability_denial_profile_v1,
                RecoveryEligibilityCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryEligibilityForbiddenCapability.AUTHORIZES_RECOVERY,
                    )
                ),
            ),
        )
        for validator, candidate in invalid_cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryEligibilityDescriptorRejected):
                    validator(candidate)  # type: ignore[arg-type]

    def test_top_level_profile_rejects_version_nested_type_and_value_drift(
        self,
    ) -> None:
        profile = expected_recovery_eligibility_profile_v1()
        invalid_profiles = (
            replace(profile, scheme_version=2),
            replace(
                profile,
                states=RecoveryEligibilityStateProfileV1(
                    states=(RecoveryEligibilityState.RESPONSE_UNAVAILABLE,)
                ),
            ),
            replace(
                profile,
                timing=RecoveryEligibilityTimingProfileV1(
                    first_read_expiry_seconds=1,
                    unread_response_expiry_seconds=(
                        RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS
                    ),
                ),
            ),
            replace(
                profile,
                requirements=RecoveryEligibilityRequirementProfileV1(
                    requirements=(
                        RecoveryEligibilityRequirement.
                        RESPONSE_DEK_AUTHORIZATION_REQUIRED,
                    )
                ),
            ),
            replace(
                profile,
                capability_denials=RecoveryEligibilityCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryEligibilityForbiddenCapability.
                        READS_RESPONSE_CIPHERTEXT,
                    )
                ),
            ),
        )
        for candidate in invalid_profiles:
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryEligibilityDescriptorRejected):
                    validate_recovery_eligibility_profile_v1(candidate)
        with self.assertRaises(RecoveryEligibilityDescriptorRejected):
            validate_recovery_eligibility_profile_v1("not a profile")  # type: ignore[arg-type]

    def test_runtime_shapes_are_strict_tuples_and_enum_instances(self) -> None:
        with self.assertRaises(RecoveryEligibilityDescriptorRejected):
            validate_recovery_eligibility_state_profile_v1(
                RecoveryEligibilityStateProfileV1(
                    states=[  # type: ignore[arg-type]
                        RecoveryEligibilityState.RESPONSE_UNAVAILABLE,
                    ]
                )
            )
        with self.assertRaises(RecoveryEligibilityDescriptorRejected):
            validate_recovery_eligibility_requirement_profile_v1(
                RecoveryEligibilityRequirementProfileV1(
                    requirements=("SERVER_AUTHORITATIVE_STATE",)  # type: ignore[arg-type]
                )
            )
        with self.assertRaises(RecoveryEligibilityDescriptorRejected):
            validate_recovery_eligibility_timing_profile_v1(
                RecoveryEligibilityTimingProfileV1(
                    first_read_expiry_seconds=True,
                    unread_response_expiry_seconds=(
                        RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS
                    ),
                )
            )

    def test_profiles_are_frozen_and_slot_limited(self) -> None:
        profiles = (
            expected_recovery_eligibility_state_profile_v1(),
            expected_recovery_eligibility_timing_profile_v1(),
            expected_recovery_eligibility_requirement_profile_v1(),
            expected_recovery_eligibility_capability_denial_profile_v1(),
            expected_recovery_eligibility_profile_v1(),
        )
        for profile in profiles:
            with self.subTest(profile=type(profile).__name__):
                self.assertFalse(hasattr(profile, "__dict__"))
                first_field = fields(profile)[0].name
                with self.assertRaises(FrozenInstanceError):
                    setattr(profile, first_field, object())
