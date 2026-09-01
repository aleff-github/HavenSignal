"""Negative tests for inert original-report crypto v1 descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    REPORT_AAD_PURPOSE,
    REPORT_AEAD_ALGORITHM_ID,
    REPORT_AEAD_TAG_BYTES,
    REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_ATTACHMENT_MAX_BYTES,
    REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
    REPORT_ATTEMPT_ID_BYTES,
    REPORT_CONTENT_PROFILE_ID,
    REPORT_CRYPTO_PROTOCOL_VERSION,
    REPORT_DEK_BYTES,
    REPORT_ID_BYTES,
    REPORT_IMAGE_OBJECT_SLOT_MAX,
    REPORT_IMAGE_OBJECT_SLOT_MIN,
    REPORT_KEY_HANDLE_BYTES,
    REPORT_KEY_OPERATIONS_V1,
    REPORT_MAX_SCALAR_VALUES,
    REPORT_MAX_UTF8_BYTES,
    REPORT_NONCE_BYTES,
    REPORT_OBJECT_ID_BYTES,
    REPORT_OBJECT_KINDS_V1,
    REPORT_OBJECT_SUBKEY_BYTES,
    REPORT_OBJECT_SUBKEY_PURPOSE,
    REPORT_PDF_OBJECT_SLOT,
    REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_TEXT_OBJECT_SLOT,
    REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
    ReportAeadAlgorithm,
    ReportAeadProfileV1,
    ReportCiphertextEnvelopeShapeV1,
    ReportContentProfile,
    ReportCryptoDescriptorRejected,
    ReportImmutableContextShapeV1,
    ReportKeyLifecycleProfileV1,
    ReportKeyOperation,
    ReportObjectKind,
    ReportObjectKindProfileV1,
    ReportPlaintextFrameProfileV1,
    expected_report_crypto_profile_v1,
    validate_report_aead_profile_v1,
    validate_report_ciphertext_envelope_shape_v1,
    validate_report_crypto_profile_v1,
    validate_report_immutable_context_shape_v1,
    validate_report_key_lifecycle_profile_v1,
    validate_report_object_kind_profile_v1,
    validate_report_plaintext_frame_profile_v1,
)


def aead_profile() -> ReportAeadProfileV1:
    return ReportAeadProfileV1(
        scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
        algorithm_id=REPORT_AEAD_ALGORITHM_ID,
        algorithm=ReportAeadAlgorithm.XCHACHA20_POLY1305_IETF,
        report_dek_size_bytes=REPORT_DEK_BYTES,
        object_subkey_size_bytes=REPORT_OBJECT_SUBKEY_BYTES,
        nonce_size_bytes=REPORT_NONCE_BYTES,
        tag_size_bytes=REPORT_AEAD_TAG_BYTES,
    )


def plaintext_frame_profile() -> ReportPlaintextFrameProfileV1:
    return ReportPlaintextFrameProfileV1(
        scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
        content_profile_id=REPORT_CONTENT_PROFILE_ID,
        content_profile=ReportContentProfile.CANONICAL_FIXED_FRAME,
        max_scalar_values=REPORT_MAX_SCALAR_VALUES,
        max_utf8_bytes=REPORT_MAX_UTF8_BYTES,
        text_plaintext_frame_size_bytes=REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
        attachment_max_bytes=REPORT_ATTACHMENT_MAX_BYTES,
        attachment_plaintext_frame_size_bytes=(
            REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES
        ),
    )


def object_kind_profile() -> ReportObjectKindProfileV1:
    return ReportObjectKindProfileV1(
        object_kinds=REPORT_OBJECT_KINDS_V1,
        text_object_slot=REPORT_TEXT_OBJECT_SLOT,
        pdf_object_slot=REPORT_PDF_OBJECT_SLOT,
        image_object_slot_min=REPORT_IMAGE_OBJECT_SLOT_MIN,
        image_object_slot_max=REPORT_IMAGE_OBJECT_SLOT_MAX,
    )


def context_shape() -> ReportImmutableContextShapeV1:
    return ReportImmutableContextShapeV1(
        aad_purpose=REPORT_AAD_PURPOSE,
        object_subkey_purpose=REPORT_OBJECT_SUBKEY_PURPOSE,
        report_id_size_bytes=REPORT_ID_BYTES,
        attempt_id_size_bytes=REPORT_ATTEMPT_ID_BYTES,
        object_id_size_bytes=REPORT_OBJECT_ID_BYTES,
        report_key_handle_size_bytes=REPORT_KEY_HANDLE_BYTES,
    )


def envelope_shape() -> ReportCiphertextEnvelopeShapeV1:
    return ReportCiphertextEnvelopeShapeV1(
        scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
        algorithm_id=REPORT_AEAD_ALGORITHM_ID,
        content_profile_id=REPORT_CONTENT_PROFILE_ID,
        nonce_size_bytes=REPORT_NONCE_BYTES,
        text_ciphertext_and_tag_size_bytes=(
            REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES
        ),
        attachment_ciphertext_and_tag_size_bytes=(
            REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES
        ),
    )


def lifecycle_profile() -> ReportKeyLifecycleProfileV1:
    return ReportKeyLifecycleProfileV1(
        allowed_operations=REPORT_KEY_OPERATIONS_V1
    )


class ReportCryptoRegistryTests(SimpleTestCase):
    def test_constants_and_registries_are_exact(self) -> None:
        self.assertEqual(REPORT_CRYPTO_PROTOCOL_VERSION, 1)
        self.assertEqual(REPORT_AEAD_ALGORITHM_ID, 1)
        self.assertEqual(REPORT_CONTENT_PROFILE_ID, 1)
        self.assertEqual(REPORT_AAD_PURPOSE, "ORIGINAL_REPORT_OBJECT")
        self.assertEqual(REPORT_OBJECT_SUBKEY_PURPOSE, "REPORT_OBJECT_AEAD_SUBKEY")
        self.assertEqual(REPORT_DEK_BYTES, 32)
        self.assertEqual(REPORT_OBJECT_SUBKEY_BYTES, 32)
        self.assertEqual(REPORT_NONCE_BYTES, 24)
        self.assertEqual(REPORT_AEAD_TAG_BYTES, 16)
        self.assertEqual(REPORT_ID_BYTES, 16)
        self.assertEqual(REPORT_ATTEMPT_ID_BYTES, 16)
        self.assertEqual(REPORT_OBJECT_ID_BYTES, 16)
        self.assertEqual(REPORT_KEY_HANDLE_BYTES, 32)
        self.assertEqual(REPORT_MAX_SCALAR_VALUES, 5_000)
        self.assertEqual(REPORT_MAX_UTF8_BYTES, 20_000)
        self.assertEqual(REPORT_TEXT_PLAINTEXT_FRAME_BYTES, 20_005)
        self.assertEqual(REPORT_ATTACHMENT_MAX_BYTES, 5_242_880)
        self.assertEqual(REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES, 5_242_890)
        self.assertEqual(REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES, 20_021)
        self.assertEqual(REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES, 5_242_906)
        self.assertEqual(REPORT_TEXT_OBJECT_SLOT, 0)
        self.assertEqual(REPORT_PDF_OBJECT_SLOT, 1)
        self.assertEqual(REPORT_IMAGE_OBJECT_SLOT_MIN, 2)
        self.assertEqual(REPORT_IMAGE_OBJECT_SLOT_MAX, 4)
        self.assertEqual(
            {algorithm.value for algorithm in ReportAeadAlgorithm},
            {"XCHACHA20_POLY1305_IETF"},
        )
        self.assertEqual(
            {profile.value for profile in ReportContentProfile},
            {"CANONICAL_FIXED_FRAME"},
        )
        self.assertEqual(
            tuple(kind.value for kind in REPORT_OBJECT_KINDS_V1),
            ("REPORT_TEXT", "PDF", "JPEG", "PNG"),
        )
        self.assertEqual(
            tuple(operation.value for operation in REPORT_KEY_OPERATIONS_V1),
            (
                "CREATE_REPORT_KEY",
                "ENCRYPT_NEW_REPORT_OBJECT",
                "VERIFY_REPORT_ENVELOPE",
                "ACTIVATE_REPORT_KEY",
                "DECRYPT_REPORT_TEXT",
                "STREAM_ATTACHMENT_TO_SANDBOX",
                "DESTROY_REPORT_KEY",
            ),
        )

    def test_complete_profile_is_structural_and_non_authorizing(self) -> None:
        profile = validate_report_crypto_profile_v1(
            aead_profile=aead_profile(),
            plaintext_frame_profile=plaintext_frame_profile(),
            object_kind_profile=object_kind_profile(),
            immutable_context_shape=context_shape(),
            ciphertext_envelope_shape=envelope_shape(),
            key_lifecycle_profile=lifecycle_profile(),
        )
        self.assertEqual(profile, expected_report_crypto_profile_v1())
        self.assertFalse(profile.generates_report_dek)
        self.assertFalse(profile.derives_object_subkeys)
        self.assertFalse(profile.encrypts_report_objects)
        self.assertFalse(profile.decrypts_report_text)
        self.assertFalse(profile.streams_original_attachments)
        self.assertFalse(profile.exposes_report_dek)
        self.assertFalse(profile.stores_plaintext_report)
        self.assertFalse(profile.authorizes_report_use)
        for field_name in (
            "report_text",
            "attachment_bytes",
            "plaintext",
            "ciphertext",
            "nonce",
            "report_dek",
            "object_subkey",
            "aad_bytes",
            "report_key_handle",
            "operator_authorization",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(profile, field_name))


class ReportCryptoValidationTests(SimpleTestCase):
    def test_aead_profile_rejects_wrong_values(self) -> None:
        valid = aead_profile()
        self.assertEqual(validate_report_aead_profile_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, algorithm_id=2),
            replace(valid, algorithm="AES_GCM"),
            replace(valid, report_dek_size_bytes=16),
            replace(valid, object_subkey_size_bytes=16),
            replace(valid, nonce_size_bytes=12),
            replace(valid, tag_size_bytes=8),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportCryptoDescriptorRejected):
                    validate_report_aead_profile_v1(candidate)

    def test_plaintext_frame_profile_rejects_wrong_values(self) -> None:
        valid = plaintext_frame_profile()
        self.assertEqual(
            validate_report_plaintext_frame_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, content_profile_id=2),
            replace(valid, content_profile="RAW_BYTES"),
            replace(valid, max_scalar_values=5_001),
            replace(valid, max_utf8_bytes=20_001),
            replace(valid, text_plaintext_frame_size_bytes=20_004),
            replace(valid, attachment_max_bytes=5_242_881),
            replace(valid, attachment_plaintext_frame_size_bytes=5_242_889),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportCryptoDescriptorRejected):
                    validate_report_plaintext_frame_profile_v1(candidate)

    def test_object_kind_profile_rejects_drift(self) -> None:
        valid = object_kind_profile()
        self.assertEqual(validate_report_object_kind_profile_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, object_kinds=REPORT_OBJECT_KINDS_V1[:-1]),
            replace(
                valid,
                object_kinds=REPORT_OBJECT_KINDS_V1
                + (ReportObjectKind.PNG,),
            ),
            replace(valid, object_kinds=tuple(reversed(REPORT_OBJECT_KINDS_V1))),
            replace(
                valid,
                object_kinds=tuple(kind.value for kind in REPORT_OBJECT_KINDS_V1),
            ),
            replace(valid, text_object_slot=1),
            replace(valid, pdf_object_slot=0),
            replace(valid, image_object_slot_min=1),
            replace(valid, image_object_slot_max=5),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportCryptoDescriptorRejected):
                    validate_report_object_kind_profile_v1(candidate)

    def test_context_shape_rejects_actual_or_wrong_context(self) -> None:
        valid = context_shape()
        self.assertEqual(validate_report_immutable_context_shape_v1(valid), valid)
        self.assertEqual(
            {field.name for field in fields(ReportImmutableContextShapeV1)},
            {
                "aad_purpose",
                "object_subkey_purpose",
                "report_id_size_bytes",
                "attempt_id_size_bytes",
                "object_id_size_bytes",
                "report_key_handle_size_bytes",
            },
        )
        for candidate in (
            object(),
            replace(valid, aad_purpose="REPORT_NOTE"),
            replace(valid, object_subkey_purpose="REPORT_KEY"),
            replace(valid, report_id_size_bytes=15),
            replace(valid, attempt_id_size_bytes=15),
            replace(valid, object_id_size_bytes=17),
            replace(valid, report_key_handle_size_bytes=16),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportCryptoDescriptorRejected):
                    validate_report_immutable_context_shape_v1(candidate)

    def test_envelope_shape_rejects_ciphertext_drift(self) -> None:
        valid = envelope_shape()
        self.assertEqual(
            validate_report_ciphertext_envelope_shape_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, algorithm_id=2),
            replace(valid, content_profile_id=2),
            replace(valid, nonce_size_bytes=12),
            replace(valid, text_ciphertext_and_tag_size_bytes=20_020),
            replace(valid, attachment_ciphertext_and_tag_size_bytes=5_242_905),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportCryptoDescriptorRejected):
                    validate_report_ciphertext_envelope_shape_v1(candidate)

    def test_key_lifecycle_profile_rejects_changed_operations(self) -> None:
        valid = lifecycle_profile()
        self.assertEqual(
            validate_report_key_lifecycle_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            ReportKeyLifecycleProfileV1(REPORT_KEY_OPERATIONS_V1[:-1]),
            ReportKeyLifecycleProfileV1(
                REPORT_KEY_OPERATIONS_V1
                + (ReportKeyOperation.DECRYPT_REPORT_TEXT,)
            ),
            ReportKeyLifecycleProfileV1(
                tuple(reversed(REPORT_KEY_OPERATIONS_V1))
            ),
            ReportKeyLifecycleProfileV1(
                tuple(operation.value for operation in REPORT_KEY_OPERATIONS_V1)
            ),
            ReportKeyLifecycleProfileV1(
                ("GET_KEY",) + REPORT_KEY_OPERATIONS_V1[1:]
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportCryptoDescriptorRejected):
                    validate_report_key_lifecycle_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        profile = aead_profile()
        with self.assertRaises(FrozenInstanceError):
            profile.nonce_size_bytes = 12

        complete = expected_report_crypto_profile_v1()
        with self.assertRaises((FrozenInstanceError, TypeError)):
            complete.decrypts_report_text = True

    def test_controlled_error_never_echoes_unknown_value(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        with self.assertRaises(ReportCryptoDescriptorRejected) as raised:
            validate_report_immutable_context_shape_v1(
                replace(context_shape(), aad_purpose=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "report_crypto_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
