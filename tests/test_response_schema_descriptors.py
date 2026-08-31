"""Negative tests for inert Response Note schema descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RESPONSE_AAD_PURPOSE,
    RESPONSE_AAD_SCHEMA_FIELDS_V1,
    RESPONSE_AEAD_ALGORITHM_ID,
    RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
    RESPONSE_CONTENT_PROFILE_ID,
    RESPONSE_CRYPTO_PROTOCOL_VERSION,
    RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1,
    RESPONSE_FINALIZATION_ID_BYTES,
    RESPONSE_ID_BYTES,
    RESPONSE_KEY_HANDLE_BYTES,
    RESPONSE_NONCE_BYTES,
    RESPONSE_PLAINTEXT_FRAME_BYTES,
    RESPONSE_REPORT_ID_BYTES,
    ResponseSchemaDescriptorRejected,
    ResponseSchemaFieldType,
    ResponseSchemaFieldV1,
    ResponseSchemaKind,
    ResponseSchemaProfileV1,
    expected_response_schema_profile_v1,
    validate_response_schema_profile_v1,
)


class ResponseSchemaRegistryTests(SimpleTestCase):
    def test_aad_field_order_and_shapes_are_exact(self) -> None:
        self.assertEqual(
            tuple(field.name for field in RESPONSE_AAD_SCHEMA_FIELDS_V1),
            (
                "version",
                "purpose",
                "algorithm",
                "content_profile",
                "report_id",
                "response_id",
                "finalization_id",
                "response_key_handle",
                "plaintext_frame_length",
            ),
        )
        self.assertEqual(RESPONSE_AAD_SCHEMA_FIELDS_V1[0].exact_value, 1)
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[1].exact_value,
            RESPONSE_AAD_PURPOSE,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[2].exact_value,
            RESPONSE_AEAD_ALGORITHM_ID,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[3].exact_value,
            RESPONSE_CONTENT_PROFILE_ID,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[4].size_bytes,
            RESPONSE_REPORT_ID_BYTES,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[5].size_bytes,
            RESPONSE_ID_BYTES,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[6].size_bytes,
            RESPONSE_FINALIZATION_ID_BYTES,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[7].size_bytes,
            RESPONSE_KEY_HANDLE_BYTES,
        )
        self.assertEqual(
            RESPONSE_AAD_SCHEMA_FIELDS_V1[8].exact_value,
            RESPONSE_PLAINTEXT_FRAME_BYTES,
        )

    def test_envelope_field_order_and_shapes_are_exact(self) -> None:
        self.assertEqual(
            tuple(field.name for field in RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1),
            (
                "version",
                "algorithm",
                "content_profile",
                "report_id",
                "response_id",
                "finalization_id",
                "response_key_handle",
                "nonce",
                "ciphertext_and_tag",
            ),
        )
        self.assertEqual(RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1[0].exact_value, 1)
        self.assertEqual(
            RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1[1].exact_value,
            RESPONSE_AEAD_ALGORITHM_ID,
        )
        self.assertEqual(
            RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1[2].exact_value,
            RESPONSE_CONTENT_PROFILE_ID,
        )
        self.assertEqual(
            RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1[7].size_bytes,
            RESPONSE_NONCE_BYTES,
        )
        self.assertEqual(
            RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1[8].size_bytes,
            RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
        )

    def test_schema_profile_is_content_free_and_non_authorizing(self) -> None:
        validated = validate_response_schema_profile_v1(
            expected_response_schema_profile_v1()
        )
        self.assertFalse(validated.encodes_cbor)
        self.assertFalse(validated.parses_cbor)
        self.assertFalse(validated.holds_context_values)
        self.assertFalse(validated.holds_ciphertext)
        self.assertFalse(validated.authorizes_response_use)
        for field_name in (
            "report_id",
            "response_id",
            "finalization_id",
            "response_key_handle",
            "nonce",
            "ciphertext",
            "aad_bytes",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class ResponseSchemaValidationTests(SimpleTestCase):
    def test_profile_rejects_wrong_schema_kind_version_and_field_order(self) -> None:
        valid = expected_response_schema_profile_v1()
        self.assertEqual(validate_response_schema_profile_v1(valid).profile, valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, aad_schema_kind=ResponseSchemaKind.CIPHERTEXT_ENVELOPE),
            replace(valid, envelope_schema_kind=ResponseSchemaKind.AAD),
            replace(valid, aad_fields=tuple(reversed(valid.aad_fields))),
            replace(
                valid,
                envelope_fields=valid.envelope_fields[:-1],
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseSchemaDescriptorRejected):
                    validate_response_schema_profile_v1(candidate)

    def test_profile_rejects_changed_or_value_bearing_fields(self) -> None:
        valid = expected_response_schema_profile_v1()
        changed_aad = (
            ResponseSchemaFieldV1(
                "report_id",
                ResponseSchemaFieldType.BYTES,
                RESPONSE_REPORT_ID_BYTES,
                b"R" * RESPONSE_REPORT_ID_BYTES,
            ),
        ) + valid.aad_fields[1:]
        changed_envelope = valid.envelope_fields[:-1] + (
            ResponseSchemaFieldV1(
                "ciphertext_and_tag",
                ResponseSchemaFieldType.BYTES,
                RESPONSE_CIPHERTEXT_AND_TAG_BYTES - 1,
                None,
            ),
        )
        for candidate in (
            replace(valid, aad_fields=changed_aad),
            replace(valid, envelope_fields=changed_envelope),
            replace(
                valid,
                aad_fields=valid.aad_fields
                + (ResponseSchemaFieldV1("extra", "TEXT", None, None),),
            ),
            replace(valid, aad_fields=list(valid.aad_fields)),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseSchemaDescriptorRejected):
                    validate_response_schema_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        field = RESPONSE_AAD_SCHEMA_FIELDS_V1[0]
        with self.assertRaises(FrozenInstanceError):
            field.name = "changed"

        validated = validate_response_schema_profile_v1(
            expected_response_schema_profile_v1()
        )
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.encodes_cbor = True

    def test_schema_fields_are_metadata_only(self) -> None:
        self.assertEqual(
            {field.name for field in fields(ResponseSchemaFieldV1)},
            {"name", "field_type", "size_bytes", "exact_value"},
        )
        self.assertEqual(
            {field.value for field in ResponseSchemaFieldType},
            {"UINT", "TEXT", "BYTES"},
        )
        self.assertEqual(
            {kind.value for kind in ResponseSchemaKind},
            {"AAD", "CIPHERTEXT_ENVELOPE"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "RESPONSE_SCHEMA_SENTINEL"
        valid = expected_response_schema_profile_v1()
        with self.assertRaises(ResponseSchemaDescriptorRejected) as raised:
            validate_response_schema_profile_v1(
                replace(valid, aad_schema_kind=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "response_schema_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
