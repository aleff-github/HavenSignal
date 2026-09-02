"""Negative tests for inert recovery verifier record descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_VERIFIER_RECORD_FIELDS_V1,
    RECOVERY_VERIFIER_RECORD_FORBIDDEN_MATERIALS_V1,
    RECOVERY_VERIFIER_RECORD_PROFILE_VERSION,
    RECOVERY_VERIFIER_RECORD_REQUIREMENTS_V1,
    RECOVERY_VERIFIER_RECORD_TAG_BYTES,
    RecoveryVerifierRecordDescriptorRejected,
    RecoveryVerifierRecordField,
    RecoveryVerifierRecordFieldProfileV1,
    RecoveryVerifierRecordForbiddenMaterial,
    RecoveryVerifierRecordForbiddenMaterialProfileV1,
    RecoveryVerifierRecordProfileV1,
    RecoveryVerifierRecordRequirement,
    RecoveryVerifierRecordRequirementProfileV1,
    StructurallyValidRecoveryVerifierRecordProfileV1,
    expected_recovery_verifier_record_field_profile_v1,
    expected_recovery_verifier_record_forbidden_material_profile_v1,
    expected_recovery_verifier_record_profile_v1,
    expected_recovery_verifier_record_requirement_profile_v1,
    validate_recovery_verifier_record_field_profile_v1,
    validate_recovery_verifier_record_forbidden_material_profile_v1,
    validate_recovery_verifier_record_profile_v1,
    validate_recovery_verifier_record_requirement_profile_v1,
)


class RecoveryVerifierRecordRegistryTests(SimpleTestCase):
    def test_version_fields_requirements_and_forbidden_materials_are_exact(
        self,
    ) -> None:
        self.assertEqual(RECOVERY_VERIFIER_RECORD_PROFILE_VERSION, 1)
        self.assertEqual(RECOVERY_VERIFIER_RECORD_TAG_BYTES, 32)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_RECORD_FIELDS_V1),
            ("SCHEME_VERSION", "VERIFIER_KEY_ID", "VERIFIER_TAG"),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_VERIFIER_RECORD_REQUIREMENTS_V1),
            (
                "STORED_WITH_PUBLIC_TICKET_ID",
                "SERVER_CONTROLLED_KEY_ID",
                "KEY_ID_NOT_REPORTER_SUPPLIED",
                "FULL_LENGTH_TAG",
                "NO_SECRET_PLAINTEXT",
                "NO_RAW_VERIFICATION_KEY",
                "DATABASE_ALONE_CANNOT_TEST_SECRET",
                "REMOVED_WITH_RECOVERY_STATE",
                "INVALIDATED_AT_RESPONSE_EXPIRY_OR_TERMINAL_DESTRUCTION",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in RECOVERY_VERIFIER_RECORD_FORBIDDEN_MATERIALS_V1
            ),
            (
                "RECOVERY_SECRET",
                "RAW_VERIFICATION_KEY",
                "RAW_HMAC_MESSAGE",
                "REPORT_TEXT",
                "ATTACHMENT_CONTENT",
                "RESPONSE_DEK",
                "REPORT_DEK",
                "OPERATOR_IDENTITY",
                "AUDIT_HISTORY_MUTATION_CAPABILITY",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_verifier_record_profile_v1(
            expected_recovery_verifier_record_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryVerifierRecordProfileV1,
        )
        self.assertFalse(validated.stores_secret)
        self.assertFalse(validated.stores_raw_verifier_key)
        self.assertFalse(validated.stores_raw_hmac_message)
        self.assertFalse(validated.stores_response_dek)
        self.assertFalse(validated.computes_verifier)
        self.assertFalse(validated.tests_candidate_secret)
        self.assertFalse(validated.performs_lookup)
        self.assertFalse(validated.writes_database)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "ticket_id",
            "recovery_secret",
            "verifier_key_id",
            "verifier_tag",
            "raw_key",
            "raw_hmac_message",
            "response_dek",
            "report_dek",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryVerifierRecordValidationTests(SimpleTestCase):
    def test_component_profiles_accept_only_reviewed_metadata(self) -> None:
        self.assertEqual(
            validate_recovery_verifier_record_field_profile_v1(
                expected_recovery_verifier_record_field_profile_v1()
            ),
            expected_recovery_verifier_record_field_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_record_requirement_profile_v1(
                expected_recovery_verifier_record_requirement_profile_v1()
            ),
            expected_recovery_verifier_record_requirement_profile_v1(),
        )
        self.assertEqual(
            validate_recovery_verifier_record_forbidden_material_profile_v1(
                expected_recovery_verifier_record_forbidden_material_profile_v1()
            ),
            expected_recovery_verifier_record_forbidden_material_profile_v1(),
        )

    def test_component_profiles_reject_drift(self) -> None:
        invalid_cases = (
            (
                validate_recovery_verifier_record_field_profile_v1,
                RecoveryVerifierRecordFieldProfileV1(
                    fields=RECOVERY_VERIFIER_RECORD_FIELDS_V1[:-1],
                    verifier_tag_size_bytes=RECOVERY_VERIFIER_RECORD_TAG_BYTES,
                ),
            ),
            (
                validate_recovery_verifier_record_field_profile_v1,
                RecoveryVerifierRecordFieldProfileV1(
                    fields=tuple(reversed(RECOVERY_VERIFIER_RECORD_FIELDS_V1)),
                    verifier_tag_size_bytes=RECOVERY_VERIFIER_RECORD_TAG_BYTES,
                ),
            ),
            (
                validate_recovery_verifier_record_field_profile_v1,
                RecoveryVerifierRecordFieldProfileV1(
                    fields=RECOVERY_VERIFIER_RECORD_FIELDS_V1,
                    verifier_tag_size_bytes=True,
                ),
            ),
            (
                validate_recovery_verifier_record_field_profile_v1,
                RecoveryVerifierRecordFieldProfileV1(
                    fields=RECOVERY_VERIFIER_RECORD_FIELDS_V1,
                    verifier_tag_size_bytes=16,
                ),
            ),
            (
                validate_recovery_verifier_record_requirement_profile_v1,
                RecoveryVerifierRecordRequirementProfileV1(
                    requirements=(
                        RecoveryVerifierRecordRequirement.
                        STORED_WITH_PUBLIC_TICKET_ID,
                    )
                ),
            ),
            (
                validate_recovery_verifier_record_forbidden_material_profile_v1,
                RecoveryVerifierRecordForbiddenMaterialProfileV1(
                    forbidden_materials=(
                        RecoveryVerifierRecordForbiddenMaterial.
                        RECOVERY_SECRET,
                    )
                ),
            ),
        )
        for validator, candidate in invalid_cases:
            with self.subTest(validator=validator.__name__, candidate=candidate):
                with self.assertRaises(RecoveryVerifierRecordDescriptorRejected):
                    validator(candidate)

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_verifier_record_profile_v1()
        self.assertEqual(
            validate_recovery_verifier_record_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(
                valid,
                fields=RecoveryVerifierRecordFieldProfileV1(
                    fields=(RecoveryVerifierRecordField.SCHEME_VERSION,),
                    verifier_tag_size_bytes=RECOVERY_VERIFIER_RECORD_TAG_BYTES,
                ),
            ),
            replace(
                valid,
                requirements=RecoveryVerifierRecordRequirementProfileV1(
                    requirements=tuple(
                        reversed(RECOVERY_VERIFIER_RECORD_REQUIREMENTS_V1)
                    )
                ),
            ),
            replace(
                valid,
                forbidden_materials=RecoveryVerifierRecordForbiddenMaterialProfileV1(
                    forbidden_materials=(
                        RecoveryVerifierRecordForbiddenMaterial.RESPONSE_DEK,
                    )
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryVerifierRecordDescriptorRejected):
                    validate_recovery_verifier_record_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_recovery_verifier_record_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierRecordProfileV1)},
            {
                "scheme_version",
                "fields",
                "requirements",
                "forbidden_materials",
            },
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierRecordFieldProfileV1)},
            {"fields", "verifier_tag_size_bytes"},
        )
        self.assertEqual(
            {
                field.name
                for field in fields(RecoveryVerifierRecordRequirementProfileV1)
            },
            {"requirements"},
        )
        self.assertEqual(
            {
                field.name
                for field in fields(
                    RecoveryVerifierRecordForbiddenMaterialProfileV1
                )
            },
            {"forbidden_materials"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RECOVERY_VERIFIER_RECORD_SENTINEL"
        valid = expected_recovery_verifier_record_profile_v1()
        with self.assertRaises(RecoveryVerifierRecordDescriptorRejected) as raised:
            validate_recovery_verifier_record_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "recovery_verifier_record_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
