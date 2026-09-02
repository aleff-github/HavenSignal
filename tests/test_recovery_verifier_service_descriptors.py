"""Negative tests for inert Recovery Verifier Service descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_VERIFIER_SERVICE_CHANNEL_REQUIREMENTS_V1,
    RECOVERY_VERIFIER_SERVICE_CREATE_RULES_V1,
    RECOVERY_VERIFIER_SERVICE_FORBIDDEN_CAPABILITIES_V1,
    RECOVERY_VERIFIER_SERVICE_OPERATIONS_V1,
    RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION,
    RECOVERY_VERIFIER_SERVICE_VERIFY_RULES_V1,
    RecoveryVerifierServiceCapabilityDenialProfileV1,
    RecoveryVerifierServiceChannelProfileV1,
    RecoveryVerifierServiceChannelRequirement,
    RecoveryVerifierServiceCreateProfileV1,
    RecoveryVerifierServiceCreateRule,
    RecoveryVerifierServiceDescriptorRejected,
    RecoveryVerifierServiceForbiddenCapability,
    RecoveryVerifierServiceOperation,
    RecoveryVerifierServiceOperationProfileV1,
    RecoveryVerifierServiceProfileV1,
    RecoveryVerifierServiceVerifyProfileV1,
    RecoveryVerifierServiceVerifyRule,
    StructurallyValidRecoveryVerifierServiceProfileV1,
    expected_recovery_verifier_service_capability_denial_profile_v1,
    expected_recovery_verifier_service_channel_profile_v1,
    expected_recovery_verifier_service_create_profile_v1,
    expected_recovery_verifier_service_operation_profile_v1,
    expected_recovery_verifier_service_profile_v1,
    expected_recovery_verifier_service_verify_profile_v1,
    validate_recovery_verifier_service_capability_denial_profile_v1,
    validate_recovery_verifier_service_channel_profile_v1,
    validate_recovery_verifier_service_create_profile_v1,
    validate_recovery_verifier_service_operation_profile_v1,
    validate_recovery_verifier_service_profile_v1,
    validate_recovery_verifier_service_verify_profile_v1,
)


class RecoveryVerifierServiceRegistryTests(SimpleTestCase):
    def test_version_operations_channel_rules_and_denials_are_exact(self) -> None:
        self.assertEqual(RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_SERVICE_OPERATIONS_V1),
            (
                "CREATE_ONLY_FOR_NEW_SUBMISSION_ATTEMPT",
                "BOOLEAN_VERIFY_FOR_RECOVERY",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_VERIFIER_SERVICE_CHANNEL_REQUIREMENTS_V1
            ),
            (
                "AUTHENTICATED",
                "ENCRYPTED",
                "BOUNDED",
                "BODY_EXCLUDED_FROM_PROXY_LOGS",
                "CREDENTIAL_FIELDS_EXCLUDED_FROM_APPLICATION_LOGS",
                "CREDENTIAL_FIELDS_EXCLUDED_FROM_AUDIT_TRACING_AND_ERROR_LOGS",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_SERVICE_CREATE_RULES_V1),
            (
                "REPORTER_GATEWAY_TRANSIENT_INPUT_ONLY",
                "BOUND_TO_ONE_CURRENT_UNACCEPTED_SUBMISSION_ATTEMPT",
                "CANNOT_PRODUCE_OR_REPLACE_EXISTING_TICKET_VERIFIER",
                "RETURNS_ONLY_VERSION_KEY_ID_AND_VERIFIER_TAG",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_SERVICE_VERIFY_RULES_V1),
            (
                "RECOVERY_GATEWAY_POST_INPUT_ONLY",
                "RETURNS_BOOLEAN_AUTHORIZATION_RESULT_ONLY",
                "NEVER_RETURNS_EXPECTED_TAG",
                "NEVER_RETURNS_PARTIAL_MATCH_INFORMATION",
                "VERIFIER_SUCCESS_IS_NOT_RESPONSE_DEK_AUTHORIZATION",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_VERIFIER_SERVICE_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "IMPLEMENTS_SERVICE_CALL",
                "GENERATES_CREDENTIALS",
                "COMPUTES_HMAC",
                "COMPARES_TAGS",
                "PERSISTS_VERIFIER_RECORD",
                "PERFORMS_LOOKUP",
                "ACCEPTS_REPORTER_SUPPLIED_KEY_ID",
                "RETURNS_RAW_VERIFIER_KEY",
                "RETURNS_EXPECTED_TAG",
                "RETURNS_PARTIAL_MATCH_DETAIL",
                "READS_RESPONSE_STATE",
                "CALLS_KEY_SERVICE",
                "AUTHORIZES_RESPONSE_DEK_USE",
                "LOGS_CREDENTIALS",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_RECOVERY",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_verifier_service_profile_v1(
            expected_recovery_verifier_service_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryVerifierServiceProfileV1,
        )
        self.assertFalse(validated.implements_service_call)
        self.assertFalse(validated.generates_credentials)
        self.assertFalse(validated.computes_hmac)
        self.assertFalse(validated.compares_tags)
        self.assertFalse(validated.persists_verifier_record)
        self.assertFalse(validated.performs_lookup)
        self.assertFalse(validated.returns_raw_verifier_key)
        self.assertFalse(validated.returns_expected_tag)
        self.assertFalse(validated.returns_partial_match_detail)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.authorizes_response_dek_use)
        self.assertFalse(validated.logs_credentials)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "verifier_key",
            "expected_tag",
            "response_dek",
            "endpoint",
            "service_url",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryVerifierServiceValidationTests(SimpleTestCase):
    def test_component_profiles_accept_only_reviewed_metadata(self) -> None:
        self.assertEqual(
            validate_recovery_verifier_service_operation_profile_v1(
                expected_recovery_verifier_service_operation_profile_v1()
            ),
            expected_recovery_verifier_service_operation_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_service_channel_profile_v1(
                expected_recovery_verifier_service_channel_profile_v1()
            ),
            expected_recovery_verifier_service_channel_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_service_create_profile_v1(
                expected_recovery_verifier_service_create_profile_v1()
            ),
            expected_recovery_verifier_service_create_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_service_verify_profile_v1(
                expected_recovery_verifier_service_verify_profile_v1()
            ),
            expected_recovery_verifier_service_verify_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_service_capability_denial_profile_v1(
                expected_recovery_verifier_service_capability_denial_profile_v1()
            ),
            expected_recovery_verifier_service_capability_denial_profile_v1(),
        )

    def test_component_profiles_reject_drift(self) -> None:
        invalid_cases = (
            (
                validate_recovery_verifier_service_operation_profile_v1,
                RecoveryVerifierServiceOperationProfileV1(
                    operations=RECOVERY_VERIFIER_SERVICE_OPERATIONS_V1[:-1]
                ),
            ),
            (
                validate_recovery_verifier_service_channel_profile_v1,
                RecoveryVerifierServiceChannelProfileV1(
                    requirements=(
                        RecoveryVerifierServiceChannelRequirement.AUTHENTICATED,
                    )
                ),
            ),
            (
                validate_recovery_verifier_service_create_profile_v1,
                RecoveryVerifierServiceCreateProfileV1(
                    rules=(
                        RecoveryVerifierServiceCreateRule.
                        RETURNS_ONLY_VERSION_KEY_ID_AND_VERIFIER_TAG,
                    )
                ),
            ),
            (
                validate_recovery_verifier_service_verify_profile_v1,
                RecoveryVerifierServiceVerifyProfileV1(
                    rules=(
                        RecoveryVerifierServiceVerifyRule.
                        RETURNS_BOOLEAN_AUTHORIZATION_RESULT_ONLY,
                    )
                ),
            ),
            (
                validate_recovery_verifier_service_capability_denial_profile_v1,
                RecoveryVerifierServiceCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryVerifierServiceForbiddenCapability.
                        AUTHORIZES_RECOVERY,
                    )
                ),
            ),
        )
        for validator, candidate in invalid_cases:
            with self.subTest(validator=validator.__name__, candidate=candidate):
                with self.assertRaises(RecoveryVerifierServiceDescriptorRejected):
                    validator(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_verifier_service_profile_v1()
        self.assertEqual(
            validate_recovery_verifier_service_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(
                valid,
                operations=RecoveryVerifierServiceOperationProfileV1(
                    operations=(
                        RecoveryVerifierServiceOperation.
                        BOOLEAN_VERIFY_FOR_RECOVERY,
                    )
                ),
            ),
            replace(
                valid,
                channel=RecoveryVerifierServiceChannelProfileV1(
                    requirements=tuple(
                        reversed(RECOVERY_VERIFIER_SERVICE_CHANNEL_REQUIREMENTS_V1)
                    )
                ),
            ),
            replace(
                valid,
                create=RecoveryVerifierServiceCreateProfileV1(
                    rules=RECOVERY_VERIFIER_SERVICE_CREATE_RULES_V1[:-1]
                ),
            ),
            replace(
                valid,
                verify=RecoveryVerifierServiceVerifyProfileV1(
                    rules=RECOVERY_VERIFIER_SERVICE_VERIFY_RULES_V1[:-1]
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryVerifierServiceDescriptorRejected):
                    validate_recovery_verifier_service_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_recovery_verifier_service_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierServiceProfileV1)},
            {
                "scheme_version",
                "operations",
                "channel",
                "create",
                "verify",
                "capability_denials",
            },
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierServiceOperationProfileV1)},
            {"operations"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RECOVERY_VERIFIER_SERVICE_SENTINEL"
        valid = expected_recovery_verifier_service_profile_v1()
        with self.assertRaises(RecoveryVerifierServiceDescriptorRejected) as raised:
            validate_recovery_verifier_service_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "recovery_verifier_service_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
