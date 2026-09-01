"""Negative tests for inert recovery key lifecycle descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION,
    RECOVERY_VERIFIER_KEY_BYTES,
    RECOVERY_VERIFIER_KEY_FORBIDDEN_LOCATIONS_V1,
    RECOVERY_VERIFIER_KEY_LIFECYCLE_REQUIREMENTS_V1,
    RECOVERY_VERIFIER_KEY_SEPARATIONS_V1,
    RECOVERY_VERIFIER_KEY_STATES_V1,
    RecoveryKeyLifecycleDescriptorRejected,
    RecoveryVerifierKeyForbiddenLocation,
    RecoveryVerifierKeyLifecycleProfileV1,
    RecoveryVerifierKeyLifecycleRequirement,
    RecoveryVerifierKeyLifecycleRequirementProfileV1,
    RecoveryVerifierKeyLocationPolicyV1,
    RecoveryVerifierKeySeparation,
    RecoveryVerifierKeySeparationProfileV1,
    RecoveryVerifierKeySizeProfileV1,
    RecoveryVerifierKeyState,
    RecoveryVerifierKeyStateProfileV1,
    StructurallyValidRecoveryVerifierKeyLifecycleProfileV1,
    expected_recovery_verifier_key_lifecycle_profile_v1,
    expected_recovery_verifier_key_lifecycle_requirement_profile_v1,
    expected_recovery_verifier_key_location_policy_v1,
    expected_recovery_verifier_key_separation_profile_v1,
    expected_recovery_verifier_key_size_profile_v1,
    expected_recovery_verifier_key_state_profile_v1,
    validate_recovery_verifier_key_lifecycle_profile_v1,
    validate_recovery_verifier_key_lifecycle_requirement_profile_v1,
    validate_recovery_verifier_key_location_policy_v1,
    validate_recovery_verifier_key_separation_profile_v1,
    validate_recovery_verifier_key_size_profile_v1,
    validate_recovery_verifier_key_state_profile_v1,
)


class RecoveryKeyLifecycleRegistryTests(SimpleTestCase):
    def test_version_size_states_separations_locations_and_requirements_are_exact(
        self,
    ) -> None:
        self.assertEqual(RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION, 1)
        self.assertEqual(RECOVERY_VERIFIER_KEY_BYTES, 32)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_KEY_STATES_V1),
            (
                "ACTIVE_FOR_CREATION",
                "RETIRED_VERIFY_ONLY",
                "DESTROYED_AFTER_NO_ELIGIBLE_REFERENCES",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_KEY_SEPARATIONS_V1),
            (
                "DJANGO_SECRET_KEY",
                "REPORT_DEK",
                "RESPONSE_DEK",
                "ENCRYPTION_KEY",
                "WRAPPING_KEY",
                "AUDIT_KEY",
                "EXPORT_KEY",
                "TLS_KEY",
                "CAPTCHA_KEY",
                "CSRF_KEY",
                "SESSION_KEY",
                "SERVICE_AUTHENTICATION_KEY",
            ),
        )
        self.assertEqual(
            tuple(
                item.value for item in RECOVERY_VERIFIER_KEY_FORBIDDEN_LOCATIONS_V1
            ),
            (
                "SOURCE_CODE",
                "DJANGO_SETTINGS",
                "APPLICATION_DATABASE",
                "APPLICATION_LOG",
                "AUDIT_EVENT",
                "BROWSER_STORAGE",
                "REPORTER_RESPONSE",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_VERIFIER_KEY_LIFECYCLE_REQUIREMENTS_V1
            ),
            (
                "SERVICE_SELECTED_KEY_ID",
                "ONE_ACTIVE_CREATION_VERSION",
                "RETIRED_VERIFY_ONLY",
                "NO_SILENT_VERSION_FALLBACK",
                "DESTROY_AFTER_NO_ELIGIBLE_RECORDS",
                "RESTORE_PROOF_BEFORE_DESTRUCTION",
                "LOSS_FAILS_CLOSED",
                "NO_RESPONSE_DEK_AUTHORITY",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_verifier_key_lifecycle_profile_v1(
            expected_recovery_verifier_key_lifecycle_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryVerifierKeyLifecycleProfileV1,
        )
        self.assertFalse(validated.generates_key)
        self.assertFalse(validated.stores_key)
        self.assertFalse(validated.selects_key_for_request)
        self.assertFalse(validated.rotates_key)
        self.assertFalse(validated.destroys_key)
        self.assertFalse(validated.rewrites_verifier)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.authorizes_response_dek_use)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "verifier_tag",
            "verifier_key",
            "raw_key",
            "key_material",
            "response_note",
            "response_dek",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryKeyLifecycleValidationTests(SimpleTestCase):
    def test_component_profiles_accept_only_reviewed_metadata(self) -> None:
        self.assertEqual(
            validate_recovery_verifier_key_size_profile_v1(
                expected_recovery_verifier_key_size_profile_v1()
            ),
            expected_recovery_verifier_key_size_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_key_state_profile_v1(
                expected_recovery_verifier_key_state_profile_v1()
            ),
            expected_recovery_verifier_key_state_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_key_separation_profile_v1(
                expected_recovery_verifier_key_separation_profile_v1()
            ),
            expected_recovery_verifier_key_separation_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_key_location_policy_v1(
                expected_recovery_verifier_key_location_policy_v1()
            ),
            expected_recovery_verifier_key_location_policy_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_key_lifecycle_requirement_profile_v1(
                expected_recovery_verifier_key_lifecycle_requirement_profile_v1()
            ),
            expected_recovery_verifier_key_lifecycle_requirement_profile_v1(),
        )

    def test_component_profiles_reject_drift(self) -> None:
        invalid_cases = (
            (
                validate_recovery_verifier_key_size_profile_v1,
                RecoveryVerifierKeySizeProfileV1(key_size_bytes=16),
            ),
            (
                validate_recovery_verifier_key_size_profile_v1,
                RecoveryVerifierKeySizeProfileV1(key_size_bytes=True),
            ),
            (
                validate_recovery_verifier_key_state_profile_v1,
                RecoveryVerifierKeyStateProfileV1(
                    states=RECOVERY_VERIFIER_KEY_STATES_V1[:-1]
                ),
            ),
            (
                validate_recovery_verifier_key_state_profile_v1,
                RecoveryVerifierKeyStateProfileV1(
                    states=tuple(reversed(RECOVERY_VERIFIER_KEY_STATES_V1))
                ),
            ),
            (
                validate_recovery_verifier_key_separation_profile_v1,
                RecoveryVerifierKeySeparationProfileV1(
                    separated_from=(
                        RecoveryVerifierKeySeparation.RESPONSE_DEK,
                    )
                ),
            ),
            (
                validate_recovery_verifier_key_location_policy_v1,
                RecoveryVerifierKeyLocationPolicyV1(
                    forbidden_locations=(
                        RecoveryVerifierKeyForbiddenLocation.SOURCE_CODE,
                    )
                ),
            ),
            (
                validate_recovery_verifier_key_lifecycle_requirement_profile_v1,
                RecoveryVerifierKeyLifecycleRequirementProfileV1(
                    requirements=(
                        RecoveryVerifierKeyLifecycleRequirement.
                        ONE_ACTIVE_CREATION_VERSION,
                    )
                ),
            ),
        )
        for validator, candidate in invalid_cases:
            with self.subTest(validator=validator.__name__, candidate=candidate):
                with self.assertRaises(RecoveryKeyLifecycleDescriptorRejected):
                    validator(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_verifier_key_lifecycle_profile_v1()
        self.assertEqual(
            validate_recovery_verifier_key_lifecycle_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(
                valid,
                key_size=RecoveryVerifierKeySizeProfileV1(key_size_bytes=64),
            ),
            replace(
                valid,
                states=RecoveryVerifierKeyStateProfileV1(
                    states=(
                        RecoveryVerifierKeyState.ACTIVE_FOR_CREATION,
                    )
                ),
            ),
            replace(
                valid,
                separation=RecoveryVerifierKeySeparationProfileV1(
                    separated_from=(
                        RecoveryVerifierKeySeparation.DJANGO_SECRET_KEY,
                    )
                ),
            ),
            replace(
                valid,
                location_policy=RecoveryVerifierKeyLocationPolicyV1(
                    forbidden_locations=(
                        RecoveryVerifierKeyForbiddenLocation.APPLICATION_LOG,
                    )
                ),
            ),
            replace(
                valid,
                requirements=RecoveryVerifierKeyLifecycleRequirementProfileV1(
                    requirements=(
                        RecoveryVerifierKeyLifecycleRequirement.
                        NO_RESPONSE_DEK_AUTHORITY,
                    )
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryKeyLifecycleDescriptorRejected):
                    validate_recovery_verifier_key_lifecycle_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_recovery_verifier_key_lifecycle_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierKeyLifecycleProfileV1)},
            {
                "scheme_version",
                "key_size",
                "states",
                "separation",
                "location_policy",
                "requirements",
            },
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierKeySizeProfileV1)},
            {"key_size_bytes"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierKeyStateProfileV1)},
            {"states"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierKeySeparationProfileV1)},
            {"separated_from"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierKeyLocationPolicyV1)},
            {"forbidden_locations"},
        )
        self.assertEqual(
            {
                field.name
                for field in fields(
                    RecoveryVerifierKeyLifecycleRequirementProfileV1
                )
            },
            {"requirements"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RECOVERY_KEY_LIFECYCLE_SENTINEL"
        valid = expected_recovery_verifier_key_lifecycle_profile_v1()
        with self.assertRaises(RecoveryKeyLifecycleDescriptorRejected) as raised:
            validate_recovery_verifier_key_lifecycle_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "recovery_key_lifecycle_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
