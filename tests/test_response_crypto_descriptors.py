"""Negative tests for inert Response Note crypto v1 descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RESPONSE_AAD_PURPOSE,
    RESPONSE_AEAD_ALGORITHM_ID,
    RESPONSE_AEAD_TAG_BYTES,
    RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
    RESPONSE_CONTENT_PROFILE_ID,
    RESPONSE_CRYPTO_PROTOCOL_VERSION,
    RESPONSE_DEK_BYTES,
    RESPONSE_FINALIZATION_ID_BYTES,
    RESPONSE_ID_BYTES,
    RESPONSE_KEY_HANDLE_BYTES,
    RESPONSE_KEY_OPERATIONS_V1,
    RESPONSE_MAX_SCALAR_VALUES,
    RESPONSE_MAX_UTF8_BYTES,
    RESPONSE_NONCE_BYTES,
    RESPONSE_PLAINTEXT_FRAME_BYTES,
    RESPONSE_REPORT_ID_BYTES,
    ResponseAeadAlgorithm,
    ResponseAeadProfileV1,
    ResponseCiphertextEnvelopeShapeV1,
    ResponseContentProfile,
    ResponseCryptoDescriptorRejected,
    ResponseImmutableContextShapeV1,
    ResponseKeyLifecycleProfileV1,
    ResponseKeyOperation,
    ResponsePlaintextFrameProfileV1,
    validate_response_aead_profile_v1,
    validate_response_ciphertext_envelope_shape_v1,
    validate_response_crypto_profile_v1,
    validate_response_immutable_context_shape_v1,
    validate_response_key_lifecycle_profile_v1,
    validate_response_plaintext_frame_profile_v1,
)


def aead_profile() -> ResponseAeadProfileV1:
    return ResponseAeadProfileV1(
        scheme_version=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        algorithm_id=RESPONSE_AEAD_ALGORITHM_ID,
        algorithm=ResponseAeadAlgorithm.XCHACHA20_POLY1305_IETF,
        response_dek_size_bytes=RESPONSE_DEK_BYTES,
        nonce_size_bytes=RESPONSE_NONCE_BYTES,
        tag_size_bytes=RESPONSE_AEAD_TAG_BYTES,
    )


def plaintext_frame_profile() -> ResponsePlaintextFrameProfileV1:
    return ResponsePlaintextFrameProfileV1(
        scheme_version=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        content_profile_id=RESPONSE_CONTENT_PROFILE_ID,
        content_profile=ResponseContentProfile.CANONICAL_UTF8_FIXED_FRAME,
        max_scalar_values=RESPONSE_MAX_SCALAR_VALUES,
        max_utf8_bytes=RESPONSE_MAX_UTF8_BYTES,
        plaintext_frame_size_bytes=RESPONSE_PLAINTEXT_FRAME_BYTES,
    )


def context_shape() -> ResponseImmutableContextShapeV1:
    return ResponseImmutableContextShapeV1(
        aad_purpose=RESPONSE_AAD_PURPOSE,
        report_id_size_bytes=RESPONSE_REPORT_ID_BYTES,
        response_id_size_bytes=RESPONSE_ID_BYTES,
        finalization_id_size_bytes=RESPONSE_FINALIZATION_ID_BYTES,
        response_key_handle_size_bytes=RESPONSE_KEY_HANDLE_BYTES,
    )


def envelope_shape() -> ResponseCiphertextEnvelopeShapeV1:
    return ResponseCiphertextEnvelopeShapeV1(
        scheme_version=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        algorithm_id=RESPONSE_AEAD_ALGORITHM_ID,
        content_profile_id=RESPONSE_CONTENT_PROFILE_ID,
        nonce_size_bytes=RESPONSE_NONCE_BYTES,
        ciphertext_and_tag_size_bytes=RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
    )


def lifecycle_profile() -> ResponseKeyLifecycleProfileV1:
    return ResponseKeyLifecycleProfileV1(
        allowed_operations=RESPONSE_KEY_OPERATIONS_V1
    )


class ResponseCryptoRegistryTests(SimpleTestCase):
    def test_constants_and_registries_are_exact(self) -> None:
        self.assertEqual(RESPONSE_CRYPTO_PROTOCOL_VERSION, 1)
        self.assertEqual(RESPONSE_AEAD_ALGORITHM_ID, 1)
        self.assertEqual(RESPONSE_CONTENT_PROFILE_ID, 1)
        self.assertEqual(RESPONSE_AAD_PURPOSE, "RESPONSE_NOTE")
        self.assertEqual(RESPONSE_DEK_BYTES, 32)
        self.assertEqual(RESPONSE_NONCE_BYTES, 24)
        self.assertEqual(RESPONSE_AEAD_TAG_BYTES, 16)
        self.assertEqual(RESPONSE_PLAINTEXT_FRAME_BYTES, 20_005)
        self.assertEqual(RESPONSE_CIPHERTEXT_AND_TAG_BYTES, 20_021)
        self.assertEqual(RESPONSE_MAX_SCALAR_VALUES, 5_000)
        self.assertEqual(RESPONSE_MAX_UTF8_BYTES, 20_000)
        self.assertEqual(RESPONSE_REPORT_ID_BYTES, 16)
        self.assertEqual(RESPONSE_ID_BYTES, 16)
        self.assertEqual(RESPONSE_FINALIZATION_ID_BYTES, 16)
        self.assertEqual(RESPONSE_KEY_HANDLE_BYTES, 32)
        self.assertEqual(
            {algorithm.value for algorithm in ResponseAeadAlgorithm},
            {"XCHACHA20_POLY1305_IETF"},
        )
        self.assertEqual(
            {profile.value for profile in ResponseContentProfile},
            {"CANONICAL_UTF8_FIXED_FRAME"},
        )
        self.assertEqual(
            tuple(operation.value for operation in RESPONSE_KEY_OPERATIONS_V1),
            (
                "CREATE_AND_ENCRYPT_RESPONSE",
                "VERIFY_RESPONSE_ENVELOPE",
                "ACTIVATE_RESPONSE_KEY",
                "ARM_RESPONSE_EXPIRY",
                "DECRYPT_RESPONSE",
                "DESTROY_RESPONSE_KEY",
            ),
        )

    def test_complete_profile_is_structural_and_non_authorizing(self) -> None:
        profile = validate_response_crypto_profile_v1(
            aead_profile=aead_profile(),
            plaintext_frame_profile=plaintext_frame_profile(),
            immutable_context_shape=context_shape(),
            ciphertext_envelope_shape=envelope_shape(),
            key_lifecycle_profile=lifecycle_profile(),
        )
        self.assertFalse(profile.encrypts_response)
        self.assertFalse(profile.decrypts_response)
        self.assertFalse(profile.exposes_response_dek)
        self.assertFalse(profile.stores_plaintext_response)
        self.assertFalse(profile.authorizes_response_use)
        for field_name in (
            "response_note",
            "plaintext",
            "ciphertext",
            "nonce",
            "response_dek",
            "aad_bytes",
            "response_key_handle",
            "recovery_authorization",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(profile, field_name))


class ResponseCryptoValidationTests(SimpleTestCase):
    def test_aead_profile_rejects_wrong_values(self) -> None:
        valid = aead_profile()
        self.assertEqual(validate_response_aead_profile_v1(valid), valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, algorithm_id=2),
            replace(valid, algorithm="AES_GCM"),
            replace(valid, response_dek_size_bytes=16),
            replace(valid, nonce_size_bytes=12),
            replace(valid, tag_size_bytes=8),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseCryptoDescriptorRejected):
                    validate_response_aead_profile_v1(candidate)

    def test_plaintext_frame_profile_rejects_wrong_values(self) -> None:
        valid = plaintext_frame_profile()
        self.assertEqual(
            validate_response_plaintext_frame_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, content_profile_id=2),
            replace(valid, content_profile="RAW_UTF8"),
            replace(valid, max_scalar_values=5_001),
            replace(valid, max_utf8_bytes=20_001),
            replace(valid, plaintext_frame_size_bytes=20_004),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseCryptoDescriptorRejected):
                    validate_response_plaintext_frame_profile_v1(candidate)

    def test_context_shape_rejects_actual_or_wrong_context(self) -> None:
        valid = context_shape()
        self.assertEqual(validate_response_immutable_context_shape_v1(valid), valid)
        self.assertEqual(
            {field.name for field in fields(ResponseImmutableContextShapeV1)},
            {
                "aad_purpose",
                "report_id_size_bytes",
                "response_id_size_bytes",
                "finalization_id_size_bytes",
                "response_key_handle_size_bytes",
            },
        )
        for candidate in (
            object(),
            replace(valid, aad_purpose="REPORT_NOTE"),
            replace(valid, report_id_size_bytes=15),
            replace(valid, response_id_size_bytes=17),
            replace(valid, finalization_id_size_bytes=15),
            replace(valid, response_key_handle_size_bytes=16),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseCryptoDescriptorRejected):
                    validate_response_immutable_context_shape_v1(candidate)

    def test_envelope_shape_rejects_ciphertext_drift(self) -> None:
        valid = envelope_shape()
        self.assertEqual(
            validate_response_ciphertext_envelope_shape_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, algorithm_id=2),
            replace(valid, content_profile_id=2),
            replace(valid, nonce_size_bytes=12),
            replace(valid, ciphertext_and_tag_size_bytes=20_020),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseCryptoDescriptorRejected):
                    validate_response_ciphertext_envelope_shape_v1(candidate)

    def test_key_lifecycle_profile_rejects_changed_operations(self) -> None:
        valid = lifecycle_profile()
        self.assertEqual(
            validate_response_key_lifecycle_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            ResponseKeyLifecycleProfileV1(RESPONSE_KEY_OPERATIONS_V1[:-1]),
            ResponseKeyLifecycleProfileV1(
                RESPONSE_KEY_OPERATIONS_V1
                + (ResponseKeyOperation.DECRYPT_RESPONSE,)
            ),
            ResponseKeyLifecycleProfileV1(
                tuple(reversed(RESPONSE_KEY_OPERATIONS_V1))
            ),
            ResponseKeyLifecycleProfileV1(
                tuple(operation.value for operation in RESPONSE_KEY_OPERATIONS_V1)
            ),
            ResponseKeyLifecycleProfileV1(
                ("GET_KEY",) + RESPONSE_KEY_OPERATIONS_V1[1:]
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseCryptoDescriptorRejected):
                    validate_response_key_lifecycle_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        profile = aead_profile()
        with self.assertRaises(FrozenInstanceError):
            profile.nonce_size_bytes = 12

        complete = validate_response_crypto_profile_v1(
            aead_profile=aead_profile(),
            plaintext_frame_profile=plaintext_frame_profile(),
            immutable_context_shape=context_shape(),
            ciphertext_envelope_shape=envelope_shape(),
            key_lifecycle_profile=lifecycle_profile(),
        )
        with self.assertRaises((FrozenInstanceError, TypeError)):
            complete.decrypts_response = True

    def test_controlled_error_never_echoes_unknown_value(self) -> None:
        sentinel = "RESPONSE_NOTE_SENTINEL"
        with self.assertRaises(ResponseCryptoDescriptorRejected) as raised:
            validate_response_immutable_context_shape_v1(
                replace(context_shape(), aad_purpose=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "response_crypto_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
