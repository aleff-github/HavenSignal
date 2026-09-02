"""Negative tests for inert recovery HMAC message layout descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_HMAC_DOMAIN_LABEL,
    RECOVERY_HMAC_MESSAGE_COMPONENTS_V1,
    RECOVERY_HMAC_MESSAGE_FORBIDDEN_CAPABILITIES_V1,
    RECOVERY_HMAC_MESSAGE_PROFILE_VERSION,
    RECOVERY_HMAC_MESSAGE_REQUIREMENTS_V1,
    RECOVERY_HMAC_RECOVERY_SECRET_BYTES,
    RECOVERY_HMAC_SEPARATOR_BYTE,
    RECOVERY_HMAC_TICKET_ID_BYTES,
    RecoveryHmacMessageCapabilityDenialProfileV1,
    RecoveryHmacMessageComponent,
    RecoveryHmacMessageDescriptorRejected,
    RecoveryHmacMessageForbiddenCapability,
    RecoveryHmacMessageLayoutProfileV1,
    RecoveryHmacMessageProfileV1,
    RecoveryHmacMessageRequirement,
    RecoveryHmacMessageRequirementProfileV1,
    StructurallyValidRecoveryHmacMessageProfileV1,
    expected_recovery_hmac_message_capability_denial_profile_v1,
    expected_recovery_hmac_message_layout_profile_v1,
    expected_recovery_hmac_message_profile_v1,
    expected_recovery_hmac_message_requirement_profile_v1,
    validate_recovery_hmac_message_capability_denial_profile_v1,
    validate_recovery_hmac_message_layout_profile_v1,
    validate_recovery_hmac_message_profile_v1,
    validate_recovery_hmac_message_requirement_profile_v1,
)


class RecoveryHmacMessageRegistryTests(SimpleTestCase):
    def test_layout_constants_components_requirements_and_denials_are_exact(
        self,
    ) -> None:
        self.assertEqual(RECOVERY_HMAC_MESSAGE_PROFILE_VERSION, 1)
        self.assertEqual(
            RECOVERY_HMAC_DOMAIN_LABEL,
            "anonymous-reporting/recovery-verifier/v1",
        )
        self.assertEqual(RECOVERY_HMAC_SEPARATOR_BYTE, 0)
        self.assertEqual(RECOVERY_HMAC_TICKET_ID_BYTES, 16)
        self.assertEqual(RECOVERY_HMAC_RECOVERY_SECRET_BYTES, 32)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_HMAC_MESSAGE_COMPONENTS_V1),
            (
                "DOMAIN_LABEL_ASCII",
                "ZERO_SEPARATOR",
                "TICKET_ID_BYTES",
                "RECOVERY_SECRET_BYTES",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_HMAC_MESSAGE_REQUIREMENTS_V1),
            (
                "FIXED_ORDER",
                "DOMAIN_SEPARATED",
                "VERSION_BOUND_DOMAIN_LABEL",
                "TERMINATING_ZERO_SEPARATOR",
                "FIXED_FIELD_LENGTHS",
                "UNAMBIGUOUS_AND_PURPOSE_SPECIFIC",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_HMAC_MESSAGE_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "ACCEPTS_CREDENTIAL_VALUES",
                "CONCATENATES_BYTES",
                "COMPUTES_HMAC",
                "STORES_CANONICAL_MESSAGE",
                "STORES_RECOVERY_SECRET",
                "ACCESSES_VERIFIER_KEY",
                "RETURNS_VERIFIER_TAG",
                "LOGS_MESSAGE_OR_CREDENTIAL",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_RECOVERY",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_hmac_message_profile_v1(
            expected_recovery_hmac_message_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryHmacMessageProfileV1,
        )
        self.assertFalse(validated.accepts_credential_values)
        self.assertFalse(validated.concatenates_bytes)
        self.assertFalse(validated.computes_hmac)
        self.assertFalse(validated.stores_canonical_message)
        self.assertFalse(validated.stores_recovery_secret)
        self.assertFalse(validated.accesses_verifier_key)
        self.assertFalse(validated.returns_verifier_tag)
        self.assertFalse(validated.logs_message_or_credential)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "ticket_id_bytes",
            "recovery_secret_bytes",
            "canonical_message",
            "verifier_key",
            "verifier_tag",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryHmacMessageValidationTests(SimpleTestCase):
    def test_component_profiles_accept_only_reviewed_metadata(self) -> None:
        self.assertEqual(
            validate_recovery_hmac_message_layout_profile_v1(
                expected_recovery_hmac_message_layout_profile_v1()
            ),
            expected_recovery_hmac_message_layout_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_hmac_message_requirement_profile_v1(
                expected_recovery_hmac_message_requirement_profile_v1()
            ),
            expected_recovery_hmac_message_requirement_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_hmac_message_capability_denial_profile_v1(
                expected_recovery_hmac_message_capability_denial_profile_v1()
            ),
            expected_recovery_hmac_message_capability_denial_profile_v1(),
        )

    def test_component_profiles_reject_drift(self) -> None:
        invalid_cases = (
            replace(
                expected_recovery_hmac_message_layout_profile_v1(),
                components=RECOVERY_HMAC_MESSAGE_COMPONENTS_V1[:-1],
            ),
            replace(
                expected_recovery_hmac_message_layout_profile_v1(),
                domain_label="anonymous-reporting/other/v1",
            ),
            replace(
                expected_recovery_hmac_message_layout_profile_v1(),
                separator_byte=True,
            ),
            replace(
                expected_recovery_hmac_message_layout_profile_v1(),
                separator_byte=1,
            ),
            replace(
                expected_recovery_hmac_message_layout_profile_v1(),
                ticket_id_size_bytes=15,
            ),
            replace(
                expected_recovery_hmac_message_layout_profile_v1(),
                recovery_secret_size_bytes=16,
            ),
        )
        for candidate in invalid_cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryHmacMessageDescriptorRejected):
                    validate_recovery_hmac_message_layout_profile_v1(candidate)

        with self.assertRaises(RecoveryHmacMessageDescriptorRejected):
            validate_recovery_hmac_message_requirement_profile_v1(
                RecoveryHmacMessageRequirementProfileV1(
                    requirements=(
                        RecoveryHmacMessageRequirement.FIXED_ORDER,
                    )
                )
            )

        with self.assertRaises(RecoveryHmacMessageDescriptorRejected):
            validate_recovery_hmac_message_capability_denial_profile_v1(
                RecoveryHmacMessageCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryHmacMessageForbiddenCapability.COMPUTES_HMAC,
                    )
                )
            )

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_hmac_message_profile_v1()
        self.assertEqual(validate_recovery_hmac_message_profile_v1(valid).profile, valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(
                valid,
                layout=RecoveryHmacMessageLayoutProfileV1(
                    components=(
                        RecoveryHmacMessageComponent.RECOVERY_SECRET_BYTES,
                        RecoveryHmacMessageComponent.TICKET_ID_BYTES,
                    ),
                    domain_label=RECOVERY_HMAC_DOMAIN_LABEL,
                    separator_byte=RECOVERY_HMAC_SEPARATOR_BYTE,
                    ticket_id_size_bytes=RECOVERY_HMAC_TICKET_ID_BYTES,
                    recovery_secret_size_bytes=RECOVERY_HMAC_RECOVERY_SECRET_BYTES,
                ),
            ),
            replace(
                valid,
                requirements=RecoveryHmacMessageRequirementProfileV1(
                    requirements=tuple(
                        reversed(RECOVERY_HMAC_MESSAGE_REQUIREMENTS_V1)
                    )
                ),
            ),
            replace(
                valid,
                capability_denials=RecoveryHmacMessageCapabilityDenialProfileV1(
                    forbidden_capabilities=(
                        RecoveryHmacMessageForbiddenCapability.AUTHORIZES_RECOVERY,
                    )
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryHmacMessageDescriptorRejected):
                    validate_recovery_hmac_message_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_recovery_hmac_message_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(RecoveryHmacMessageProfileV1)},
            {"scheme_version", "layout", "requirements", "capability_denials"},
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryHmacMessageLayoutProfileV1)},
            {
                "components",
                "domain_label",
                "separator_byte",
                "ticket_id_size_bytes",
                "recovery_secret_size_bytes",
            },
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RECOVERY_HMAC_MESSAGE_SENTINEL"
        valid = expected_recovery_hmac_message_profile_v1()
        with self.assertRaises(RecoveryHmacMessageDescriptorRejected) as raised:
            validate_recovery_hmac_message_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "recovery_hmac_message_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
