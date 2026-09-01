"""Negative tests for inert original-report schema descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    REPORT_AAD_PURPOSE,
    REPORT_AAD_SCHEMA_FIELDS_V1,
    REPORT_AEAD_ALGORITHM_ID,
    REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
    REPORT_ATTEMPT_ID_BYTES,
    REPORT_CIPHERTEXT_AND_TAG_SIZE_VALUES_V1,
    REPORT_CONTENT_PROFILE_ID,
    REPORT_CRYPTO_PROTOCOL_VERSION,
    REPORT_ENVELOPE_SCHEMA_FIELDS_V1,
    REPORT_FRAME_LENGTH_VALUES_V1,
    REPORT_ID_BYTES,
    REPORT_KEY_HANDLE_BYTES,
    REPORT_NONCE_BYTES,
    REPORT_OBJECT_ID_BYTES,
    REPORT_OBJECT_KIND_VALUES_V1,
    REPORT_OBJECT_SLOT_VALUES_V1,
    REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
    ReportSchemaDescriptorRejected,
    ReportSchemaFieldType,
    ReportSchemaFieldV1,
    ReportSchemaKind,
    expected_report_schema_profile_v1,
    validate_report_schema_profile_v1,
)


class ReportSchemaRegistryTests(SimpleTestCase):
    def test_aad_field_order_and_shapes_are_exact(self) -> None:
        self.assertEqual(
            tuple(field.name for field in REPORT_AAD_SCHEMA_FIELDS_V1),
            (
                "version",
                "purpose",
                "algorithm",
                "content_profile",
                "report_id",
                "attempt_id",
                "object_id",
                "object_kind",
                "object_slot",
                "report_key_handle",
                "plaintext_frame_length",
            ),
        )
        self.assertEqual(REPORT_AAD_SCHEMA_FIELDS_V1[0].exact_value, 1)
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[1].exact_value,
            REPORT_AAD_PURPOSE,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[2].exact_value,
            REPORT_AEAD_ALGORITHM_ID,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[3].exact_value,
            REPORT_CONTENT_PROFILE_ID,
        )
        self.assertEqual(REPORT_AAD_SCHEMA_FIELDS_V1[4].size_bytes, REPORT_ID_BYTES)
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[5].size_bytes,
            REPORT_ATTEMPT_ID_BYTES,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[6].size_bytes,
            REPORT_OBJECT_ID_BYTES,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[7].allowed_values,
            REPORT_OBJECT_KIND_VALUES_V1,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[8].allowed_values,
            REPORT_OBJECT_SLOT_VALUES_V1,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[9].size_bytes,
            REPORT_KEY_HANDLE_BYTES,
        )
        self.assertEqual(
            REPORT_AAD_SCHEMA_FIELDS_V1[10].allowed_values,
            REPORT_FRAME_LENGTH_VALUES_V1,
        )

    def test_envelope_field_order_and_shapes_are_exact(self) -> None:
        self.assertEqual(
            tuple(field.name for field in REPORT_ENVELOPE_SCHEMA_FIELDS_V1),
            (
                "version",
                "algorithm",
                "content_profile",
                "report_id",
                "attempt_id",
                "object_id",
                "object_kind",
                "object_slot",
                "report_key_handle",
                "nonce",
                "ciphertext_and_tag",
            ),
        )
        self.assertEqual(REPORT_ENVELOPE_SCHEMA_FIELDS_V1[0].exact_value, 1)
        self.assertEqual(
            REPORT_ENVELOPE_SCHEMA_FIELDS_V1[1].exact_value,
            REPORT_AEAD_ALGORITHM_ID,
        )
        self.assertEqual(
            REPORT_ENVELOPE_SCHEMA_FIELDS_V1[2].exact_value,
            REPORT_CONTENT_PROFILE_ID,
        )
        self.assertEqual(
            REPORT_ENVELOPE_SCHEMA_FIELDS_V1[9].size_bytes,
            REPORT_NONCE_BYTES,
        )
        self.assertEqual(
            REPORT_ENVELOPE_SCHEMA_FIELDS_V1[10].allowed_size_bytes,
            REPORT_CIPHERTEXT_AND_TAG_SIZE_VALUES_V1,
        )
        self.assertEqual(
            REPORT_FRAME_LENGTH_VALUES_V1,
            (REPORT_TEXT_PLAINTEXT_FRAME_BYTES, REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES),
        )
        self.assertEqual(
            REPORT_CIPHERTEXT_AND_TAG_SIZE_VALUES_V1,
            (
                REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,
                REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES,
            ),
        )

    def test_schema_profile_is_content_free_and_non_authorizing(self) -> None:
        validated = validate_report_schema_profile_v1(
            expected_report_schema_profile_v1()
        )
        self.assertFalse(validated.encodes_cbor)
        self.assertFalse(validated.parses_cbor)
        self.assertFalse(validated.holds_context_values)
        self.assertFalse(validated.holds_ciphertext)
        self.assertFalse(validated.streams_attachments)
        self.assertFalse(validated.authorizes_report_use)
        for field_name in (
            "report_id",
            "attempt_id",
            "object_id",
            "report_key_handle",
            "nonce",
            "ciphertext",
            "aad_bytes",
            "attachment_bytes",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class ReportSchemaValidationTests(SimpleTestCase):
    def test_profile_rejects_wrong_schema_kind_version_and_field_order(self) -> None:
        valid = expected_report_schema_profile_v1()
        self.assertEqual(validate_report_schema_profile_v1(valid).profile, valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, aad_schema_kind=ReportSchemaKind.CIPHERTEXT_ENVELOPE),
            replace(valid, envelope_schema_kind=ReportSchemaKind.AAD),
            replace(valid, aad_fields=tuple(reversed(valid.aad_fields))),
            replace(valid, envelope_fields=valid.envelope_fields[:-1]),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportSchemaDescriptorRejected):
                    validate_report_schema_profile_v1(candidate)

    def test_profile_rejects_changed_or_value_bearing_fields(self) -> None:
        valid = expected_report_schema_profile_v1()
        changed_aad = (
            ReportSchemaFieldV1(
                "report_id",
                ReportSchemaFieldType.BYTES,
                REPORT_ID_BYTES,
                b"R" * REPORT_ID_BYTES,
                (),
                (),
            ),
        ) + valid.aad_fields[1:]
        changed_envelope = valid.envelope_fields[:-1] + (
            ReportSchemaFieldV1(
                "ciphertext_and_tag",
                ReportSchemaFieldType.BYTES,
                None,
                None,
                (),
                (REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,),
            ),
        )
        for candidate in (
            replace(valid, aad_fields=changed_aad),
            replace(valid, envelope_fields=changed_envelope),
            replace(
                valid,
                aad_fields=valid.aad_fields
                + (ReportSchemaFieldV1("extra", "TEXT", None, None, (), ()),),
            ),
            replace(valid, aad_fields=list(valid.aad_fields)),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportSchemaDescriptorRejected):
                    validate_report_schema_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        field = REPORT_AAD_SCHEMA_FIELDS_V1[0]
        with self.assertRaises(FrozenInstanceError):
            field.name = "changed"

        validated = validate_report_schema_profile_v1(
            expected_report_schema_profile_v1()
        )
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.encodes_cbor = True

    def test_schema_fields_are_metadata_only(self) -> None:
        self.assertEqual(
            {field.name for field in fields(ReportSchemaFieldV1)},
            {
                "name",
                "field_type",
                "size_bytes",
                "exact_value",
                "allowed_values",
                "allowed_size_bytes",
            },
        )
        self.assertEqual(
            {field.value for field in ReportSchemaFieldType},
            {"UINT", "TEXT", "BYTES"},
        )
        self.assertEqual(
            {kind.value for kind in ReportSchemaKind},
            {"AAD", "CIPHERTEXT_ENVELOPE"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "REPORT_SCHEMA_SENTINEL"
        valid = expected_report_schema_profile_v1()
        with self.assertRaises(ReportSchemaDescriptorRejected) as raised:
            validate_report_schema_profile_v1(
                replace(valid, aad_schema_kind=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "report_schema_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
