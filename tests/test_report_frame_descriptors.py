"""Negative tests for inert original-report plaintext-frame descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    REPORT_ATTACHMENT_FRAME_FIELDS_V1,
    REPORT_ATTACHMENT_FRAME_HEADER_BYTES,
    REPORT_ATTACHMENT_KIND_CODES_V1,
    REPORT_ATTACHMENT_KIND_FIELD_BYTES,
    REPORT_ATTACHMENT_LENGTH_FIELD_BYTES,
    REPORT_ATTACHMENT_MAX_BYTES,
    REPORT_ATTACHMENT_PADDING_REQUIRED,
    REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
    REPORT_CRYPTO_PROTOCOL_VERSION,
    REPORT_FRAME_VERSION_BYTE,
    REPORT_FRAME_VERSION_FIELD_BYTES,
    REPORT_MAX_UTF8_BYTES,
    REPORT_TEXT_FRAME_FIELDS_V1,
    REPORT_TEXT_FRAME_HEADER_BYTES,
    REPORT_TEXT_LENGTH_FIELD_BYTES,
    REPORT_TEXT_PADDING_REQUIRED,
    REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
    ReportAttachmentKindCode,
    ReportFrameDescriptorRejected,
    ReportFrameFieldType,
    ReportFrameFieldV1,
    ReportFrameKind,
    ReportPlaintextFrameLayoutV1,
    expected_report_frame_profile_v1,
    validate_report_attachment_frame_layout_v1,
    validate_report_frame_profile_v1,
    validate_report_text_frame_layout_v1,
)


def text_layout() -> ReportPlaintextFrameLayoutV1:
    return ReportPlaintextFrameLayoutV1(
        scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
        frame_kind=ReportFrameKind.REPORT_TEXT,
        total_size_bytes=REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
        fields=REPORT_TEXT_FRAME_FIELDS_V1,
        zero_padding_required=REPORT_TEXT_PADDING_REQUIRED,
    )


def attachment_layout() -> ReportPlaintextFrameLayoutV1:
    return ReportPlaintextFrameLayoutV1(
        scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
        frame_kind=ReportFrameKind.ATTACHMENT,
        total_size_bytes=REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
        fields=REPORT_ATTACHMENT_FRAME_FIELDS_V1,
        zero_padding_required=REPORT_ATTACHMENT_PADDING_REQUIRED,
    )


class ReportFrameRegistryTests(SimpleTestCase):
    def test_constants_and_registries_are_exact(self) -> None:
        self.assertEqual(REPORT_FRAME_VERSION_BYTE, 0x01)
        self.assertEqual(REPORT_FRAME_VERSION_FIELD_BYTES, 1)
        self.assertEqual(REPORT_TEXT_LENGTH_FIELD_BYTES, 4)
        self.assertEqual(REPORT_ATTACHMENT_KIND_FIELD_BYTES, 1)
        self.assertEqual(REPORT_ATTACHMENT_LENGTH_FIELD_BYTES, 8)
        self.assertEqual(REPORT_TEXT_FRAME_HEADER_BYTES, 5)
        self.assertEqual(REPORT_ATTACHMENT_FRAME_HEADER_BYTES, 10)
        self.assertTrue(REPORT_TEXT_PADDING_REQUIRED)
        self.assertTrue(REPORT_ATTACHMENT_PADDING_REQUIRED)
        self.assertEqual(
            tuple(code.value for code in REPORT_ATTACHMENT_KIND_CODES_V1),
            (0x01, 0x02, 0x03),
        )
        self.assertEqual(
            {kind.value for kind in ReportFrameKind},
            {"REPORT_TEXT", "ATTACHMENT"},
        )
        self.assertEqual(
            {field_type.value for field_type in ReportFrameFieldType},
            {
                "VERSION_BYTE",
                "OBJECT_KIND_CODE",
                "UINT32_BIG_ENDIAN",
                "UINT64_BIG_ENDIAN",
                "CANONICAL_UTF8_TEXT",
                "ACCEPTED_ORIGINAL_BYTES",
                "ZERO_PADDING",
            },
        )

    def test_text_frame_field_order_and_shapes_are_exact(self) -> None:
        self.assertEqual(
            tuple(field.name for field in REPORT_TEXT_FRAME_FIELDS_V1),
            (
                "version",
                "utf8_byte_length",
                "canonical_utf8_report_text",
                "zero_padding",
            ),
        )
        self.assertEqual(REPORT_TEXT_FRAME_FIELDS_V1[0].size_bytes, 1)
        self.assertEqual(
            REPORT_TEXT_FRAME_FIELDS_V1[0].exact_value,
            REPORT_FRAME_VERSION_BYTE,
        )
        self.assertEqual(
            REPORT_TEXT_FRAME_FIELDS_V1[1].field_type,
            ReportFrameFieldType.UINT32_BIG_ENDIAN,
        )
        self.assertEqual(
            REPORT_TEXT_FRAME_FIELDS_V1[1].max_payload_bytes,
            REPORT_MAX_UTF8_BYTES,
        )
        self.assertEqual(
            REPORT_TEXT_FRAME_FIELDS_V1[3].field_type,
            ReportFrameFieldType.ZERO_PADDING,
        )
        self.assertEqual(REPORT_TEXT_FRAME_FIELDS_V1[3].exact_value, 0)

    def test_attachment_frame_field_order_and_shapes_are_exact(self) -> None:
        self.assertEqual(
            tuple(field.name for field in REPORT_ATTACHMENT_FRAME_FIELDS_V1),
            (
                "version",
                "object_kind_code",
                "original_byte_length",
                "accepted_original_bytes",
                "zero_padding",
            ),
        )
        self.assertEqual(REPORT_ATTACHMENT_FRAME_FIELDS_V1[0].size_bytes, 1)
        self.assertEqual(
            REPORT_ATTACHMENT_FRAME_FIELDS_V1[1].field_type,
            ReportFrameFieldType.OBJECT_KIND_CODE,
        )
        self.assertEqual(
            REPORT_ATTACHMENT_FRAME_FIELDS_V1[2].field_type,
            ReportFrameFieldType.UINT64_BIG_ENDIAN,
        )
        self.assertEqual(
            REPORT_ATTACHMENT_FRAME_FIELDS_V1[2].max_payload_bytes,
            REPORT_ATTACHMENT_MAX_BYTES,
        )
        self.assertEqual(
            REPORT_ATTACHMENT_FRAME_FIELDS_V1[3].max_payload_bytes,
            REPORT_ATTACHMENT_MAX_BYTES,
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        profile = expected_report_frame_profile_v1()
        self.assertFalse(profile.accepts_plaintext)
        self.assertFalse(profile.constructs_frame)
        self.assertFalse(profile.parses_frame)
        self.assertFalse(profile.validates_padding_bytes)
        self.assertFalse(profile.inspects_attachment_bytes)
        self.assertFalse(profile.encrypts_frame)
        self.assertFalse(profile.persists_frame)
        self.assertFalse(profile.authorizes_submission)
        for field_name in (
            "report_text",
            "attachment_bytes",
            "canonical_bytes",
            "plaintext_frame",
            "ciphertext",
            "padding_bytes",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(profile, field_name))


class ReportFrameValidationTests(SimpleTestCase):
    def test_text_layout_rejects_drift(self) -> None:
        valid = text_layout()
        self.assertEqual(validate_report_text_frame_layout_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, frame_kind=ReportFrameKind.ATTACHMENT),
            replace(valid, total_size_bytes=REPORT_TEXT_PLAINTEXT_FRAME_BYTES - 1),
            replace(valid, fields=tuple(reversed(valid.fields))),
            replace(valid, zero_padding_required=False),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportFrameDescriptorRejected):
                    validate_report_text_frame_layout_v1(candidate)

    def test_attachment_layout_rejects_drift(self) -> None:
        valid = attachment_layout()
        self.assertEqual(validate_report_attachment_frame_layout_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, frame_kind=ReportFrameKind.REPORT_TEXT),
            replace(
                valid,
                total_size_bytes=REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES - 1,
            ),
            replace(valid, fields=valid.fields[:-1]),
            replace(valid, zero_padding_required=False),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportFrameDescriptorRejected):
                    validate_report_attachment_frame_layout_v1(candidate)

    def test_profile_rejects_changed_kind_codes_and_value_fields(self) -> None:
        valid = expected_report_frame_profile_v1()
        changed_text = replace(
            valid.text_frame_layout,
            fields=(
                ReportFrameFieldV1(
                    "version",
                    ReportFrameFieldType.VERSION_BYTE,
                    1,
                    2,
                    None,
                ),
            )
            + valid.text_frame_layout.fields[1:],
        )
        for candidate in (
            {"text": valid.text_frame_layout},
            (
                valid.text_frame_layout,
                valid.attachment_frame_layout,
                REPORT_ATTACHMENT_KIND_CODES_V1[:-1],
            ),
            (
                changed_text,
                valid.attachment_frame_layout,
                REPORT_ATTACHMENT_KIND_CODES_V1,
            ),
            (
                valid.text_frame_layout,
                valid.attachment_frame_layout,
                tuple(code.value for code in REPORT_ATTACHMENT_KIND_CODES_V1),
            ),
            (
                valid.text_frame_layout,
                valid.attachment_frame_layout,
                REPORT_ATTACHMENT_KIND_CODES_V1
                + (ReportAttachmentKindCode.PNG,),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportFrameDescriptorRejected):
                    if type(candidate) is tuple:
                        validate_report_frame_profile_v1(
                            text_frame_layout=candidate[0],
                            attachment_frame_layout=candidate[1],
                            attachment_kind_codes=candidate[2],
                        )
                    else:
                        validate_report_frame_profile_v1(
                            text_frame_layout=candidate,
                            attachment_frame_layout=valid.attachment_frame_layout,
                            attachment_kind_codes=REPORT_ATTACHMENT_KIND_CODES_V1,
                        )

    def test_descriptors_are_immutable(self) -> None:
        field = REPORT_TEXT_FRAME_FIELDS_V1[0]
        with self.assertRaises(FrozenInstanceError):
            field.name = "changed"

        profile = expected_report_frame_profile_v1()
        with self.assertRaises((FrozenInstanceError, TypeError)):
            profile.constructs_frame = True

    def test_frame_fields_are_metadata_only(self) -> None:
        self.assertEqual(
            {field.name for field in fields(ReportFrameFieldV1)},
            {
                "name",
                "field_type",
                "size_bytes",
                "exact_value",
                "max_payload_bytes",
            },
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "REPORT_FRAME_SENTINEL"
        valid = text_layout()
        with self.assertRaises(ReportFrameDescriptorRejected) as raised:
            validate_report_text_frame_layout_v1(
                replace(valid, frame_kind=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "report_frame_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
