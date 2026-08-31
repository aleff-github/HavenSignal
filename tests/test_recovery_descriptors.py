"""Negative tests for inert recovery credential v1 descriptors."""

import base64
from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_CREDENTIAL_PROTOCOL_VERSION,
    RECOVERY_SECRET_ENCODED_LENGTH,
    RECOVERY_SECRET_RAW_BYTES,
    RECOVERY_VERIFIER_DOMAIN_LABEL,
    RECOVERY_VERIFIER_TAG_BYTES,
    TICKET_ID_ENCODED_LENGTH,
    TICKET_ID_RAW_BYTES,
    CanonicalRecoverySecretShapeV1,
    CanonicalTicketIdShapeV1,
    RecoveryCredentialEncoding,
    RecoveryCredentialRole,
    RecoveryDescriptorRejected,
    RecoveryVerifierPurposeProfileV1,
    validate_recovery_credential_components_v1,
    validate_recovery_secret_shape_v1,
    validate_recovery_secret_text_v1,
    validate_recovery_verifier_purpose_profile_v1,
    validate_ticket_id_shape_v1,
    validate_ticket_id_text_v1,
)


def canonical_ticket_id() -> str:
    payload = bytes(range(TICKET_ID_RAW_BYTES))
    return base64.b32encode(payload).decode("ascii").rstrip("=")


def canonical_recovery_secret() -> str:
    payload = bytes(range(0x30, 0x30 + RECOVERY_SECRET_RAW_BYTES))
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def verifier_profile() -> RecoveryVerifierPurposeProfileV1:
    return RecoveryVerifierPurposeProfileV1(
        scheme_version=RECOVERY_CREDENTIAL_PROTOCOL_VERSION,
        domain_label=RECOVERY_VERIFIER_DOMAIN_LABEL,
        verifier_tag_size_bytes=RECOVERY_VERIFIER_TAG_BYTES,
    )


class RecoveryCredentialRegistryTests(SimpleTestCase):
    def test_protocol_sizes_encodings_and_domain_label_are_exact(self) -> None:
        self.assertEqual(RECOVERY_CREDENTIAL_PROTOCOL_VERSION, 1)
        self.assertEqual(TICKET_ID_RAW_BYTES, 16)
        self.assertEqual(TICKET_ID_ENCODED_LENGTH, 26)
        self.assertEqual(RECOVERY_SECRET_RAW_BYTES, 32)
        self.assertEqual(RECOVERY_SECRET_ENCODED_LENGTH, 43)
        self.assertEqual(RECOVERY_VERIFIER_TAG_BYTES, 32)
        self.assertEqual(
            RECOVERY_VERIFIER_DOMAIN_LABEL,
            "anonymous-reporting/recovery-verifier/v1",
        )
        self.assertEqual(
            {encoding.value for encoding in RecoveryCredentialEncoding},
            {
                "BASE32_RFC4648_UPPER_UNPADDED",
                "BASE64URL_RFC4648_UNPADDED",
            },
        )
        self.assertEqual(
            {role.value for role in RecoveryCredentialRole},
            {"PUBLIC_LOOKUP_IDENTIFIER", "AUTHENTICATION_SECRET"},
        )

    def test_documented_canonical_examples_are_accepted(self) -> None:
        self.assertEqual(canonical_ticket_id(), "AAAQEAYEAUDAOCAJBIFQYDIOB4")
        self.assertEqual(
            canonical_recovery_secret(),
            "MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8",
        )
        ticket_shape = validate_ticket_id_text_v1(canonical_ticket_id())
        secret_shape = validate_recovery_secret_text_v1(
            canonical_recovery_secret()
        )
        self.assertEqual(ticket_shape.raw_size_bytes, TICKET_ID_RAW_BYTES)
        self.assertEqual(
            ticket_shape.encoding,
            RecoveryCredentialEncoding.BASE32_UPPER_UNPADDED,
        )
        self.assertEqual(secret_shape.raw_size_bytes, RECOVERY_SECRET_RAW_BYTES)
        self.assertEqual(
            secret_shape.encoding,
            RecoveryCredentialEncoding.BASE64URL_UNPADDED,
        )


class RecoveryCredentialShapeTests(SimpleTestCase):
    def test_validated_shapes_do_not_retain_credential_material(self) -> None:
        ticket_id = canonical_ticket_id()
        recovery_secret = canonical_recovery_secret()
        result = validate_recovery_credential_components_v1(
            ticket_id=ticket_id,
            recovery_secret=recovery_secret,
            verifier_profile=verifier_profile(),
        )
        self.assertNotIn(ticket_id, repr(result))
        self.assertNotIn(recovery_secret, repr(result))
        self.assertFalse(result.generates_credentials)
        self.assertFalse(result.computes_verifier)
        self.assertFalse(result.stores_plaintext_secret)
        self.assertFalse(result.authorizes_recovery)

        for field_name in (
            "ticket_id",
            "recovery_secret",
            "decoded_ticket_id",
            "decoded_recovery_secret",
            "verifier_tag",
            "verifier_key",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(result, field_name))

    def test_ticket_id_rejects_noncanonical_text(self) -> None:
        valid = canonical_ticket_id()
        rejected = (
            valid.lower(),
            valid + "=",
            valid[:4] + "-" + valid[5:],
            valid[:-1],
            valid + "A",
            valid[:-1] + "0",
            valid[:-1] + "À",
            object(),
        )
        for candidate in rejected:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(RecoveryDescriptorRejected):
                    validate_ticket_id_text_v1(candidate)

    def test_recovery_secret_rejects_noncanonical_text(self) -> None:
        valid = canonical_recovery_secret()
        rejected = (
            valid + "=",
            valid.replace("-", "+"),
            valid[:-1] + "/",
            valid[:-1],
            valid + "A",
            valid[:-1] + "À",
            " " + valid[1:],
            object(),
        )
        for candidate in rejected:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(RecoveryDescriptorRejected):
                    validate_recovery_secret_text_v1(candidate)

    def test_shape_descriptors_reject_wrong_profiles(self) -> None:
        ticket_shape = validate_ticket_id_text_v1(canonical_ticket_id())
        secret_shape = validate_recovery_secret_text_v1(
            canonical_recovery_secret()
        )
        self.assertEqual(validate_ticket_id_shape_v1(ticket_shape), ticket_shape)
        self.assertEqual(
            validate_recovery_secret_shape_v1(secret_shape),
            secret_shape,
        )

        for shape in (
            replace(ticket_shape, raw_size_bytes=15),
            replace(ticket_shape, encoded_length=27),
            replace(
                ticket_shape,
                encoding=RecoveryCredentialEncoding.BASE64URL_UNPADDED,
            ),
            replace(
                ticket_shape,
                role=RecoveryCredentialRole.AUTHENTICATION_SECRET,
            ),
        ):
            with self.subTest(shape=shape):
                with self.assertRaises(RecoveryDescriptorRejected):
                    validate_ticket_id_shape_v1(shape)

        for shape in (
            replace(secret_shape, raw_size_bytes=31),
            replace(secret_shape, encoded_length=44),
            replace(
                secret_shape,
                encoding=RecoveryCredentialEncoding.BASE32_UPPER_UNPADDED,
            ),
            replace(
                secret_shape,
                role=RecoveryCredentialRole.PUBLIC_LOOKUP_IDENTIFIER,
            ),
        ):
            with self.subTest(shape=shape):
                with self.assertRaises(RecoveryDescriptorRejected):
                    validate_recovery_secret_shape_v1(shape)

    def test_verifier_profile_is_metadata_only_and_exact(self) -> None:
        profile = verifier_profile()
        self.assertEqual(
            validate_recovery_verifier_purpose_profile_v1(profile),
            profile,
        )
        self.assertEqual(
            {field.name for field in fields(RecoveryVerifierPurposeProfileV1)},
            {"scheme_version", "domain_label", "verifier_tag_size_bytes"},
        )
        self.assertFalse(hasattr(profile, "verifier_tag"))
        self.assertFalse(hasattr(profile, "verifier_key"))
        self.assertFalse(hasattr(profile, "hmac_message"))

        for candidate in (
            object(),
            replace(profile, scheme_version=2),
            replace(profile, domain_label="anonymous-reporting/other/v1"),
            replace(profile, verifier_tag_size_bytes=16),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryDescriptorRejected):
                    validate_recovery_verifier_purpose_profile_v1(candidate)

    def test_descriptors_and_result_are_immutable(self) -> None:
        ticket_shape = validate_ticket_id_text_v1(canonical_ticket_id())
        with self.assertRaises(FrozenInstanceError):
            ticket_shape.encoded_length = 27

        result = validate_recovery_credential_components_v1(
            ticket_id=canonical_ticket_id(),
            recovery_secret=canonical_recovery_secret(),
            verifier_profile=verifier_profile(),
        )
        with self.assertRaises(FrozenInstanceError):
            result.verifier_profile = verifier_profile()

    def test_controlled_error_never_echoes_unknown_secret(self) -> None:
        sentinel = "RECOVERY_SECRET_SENTINEL"
        with self.assertRaises(RecoveryDescriptorRejected) as raised:
            validate_recovery_secret_text_v1(sentinel)
        self.assertEqual(str(raised.exception), "recovery_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
