"""Negative tests for inert attachment admission descriptors."""

from dataclasses import FrozenInstanceError, replace

from django.test import SimpleTestCase

from security_interfaces import (
    ATTACHMENT_ADMISSION_PROTOCOL_VERSION,
    ATTACHMENT_EXTENSIONS_V1,
    ATTACHMENT_FILE_MAX_BYTES,
    ATTACHMENT_FILE_MIN_BYTES,
    ATTACHMENT_FILENAME_MAX_STEM_LENGTH,
    ATTACHMENT_FILENAME_MIN_STEM_LENGTH,
    ATTACHMENT_FILENAME_PATTERN,
    ATTACHMENT_IMAGE_SLOTS_MAX,
    ATTACHMENT_KINDS_V1,
    ATTACHMENT_PDF_SLOTS_MAX,
    ATTACHMENT_SLOTS_V1,
    ATTACHMENT_TOTAL_SLOTS_MAX,
    AttachmentAdmissionDescriptorRejected,
    AttachmentByteLimitProfileV1,
    AttachmentExtension,
    AttachmentFilenameProfileV1,
    AttachmentKind,
    AttachmentSlot,
    AttachmentTrustProfileV1,
    expected_attachment_admission_profile_v1,
    validate_attachment_admission_profile_v1,
)


class AttachmentAdmissionProfileTests(SimpleTestCase):
    def test_constants_match_the_approved_common_v1_profile(self) -> None:
        self.assertEqual(ATTACHMENT_ADMISSION_PROTOCOL_VERSION, 1)
        self.assertEqual(ATTACHMENT_FILE_MIN_BYTES, 1)
        self.assertEqual(ATTACHMENT_FILE_MAX_BYTES, 5_242_880)
        self.assertEqual(ATTACHMENT_PDF_SLOTS_MAX, 1)
        self.assertEqual(ATTACHMENT_IMAGE_SLOTS_MAX, 3)
        self.assertEqual(ATTACHMENT_TOTAL_SLOTS_MAX, 4)
        self.assertEqual(ATTACHMENT_FILENAME_MIN_STEM_LENGTH, 1)
        self.assertEqual(ATTACHMENT_FILENAME_MAX_STEM_LENGTH, 64)
        self.assertEqual(
            ATTACHMENT_FILENAME_PATTERN,
            r"^[A-Za-z]{1,64}\.(pdf|jpg|jpeg|png)$",
        )

    def test_kind_slot_and_extension_registries_are_closed(self) -> None:
        self.assertEqual(
            ATTACHMENT_KINDS_V1,
            (AttachmentKind.PDF, AttachmentKind.JPEG, AttachmentKind.PNG),
        )
        self.assertEqual(
            ATTACHMENT_SLOTS_V1,
            (
                AttachmentSlot.PDF,
                AttachmentSlot.IMAGE_1,
                AttachmentSlot.IMAGE_2,
                AttachmentSlot.IMAGE_3,
            ),
        )
        self.assertEqual(
            ATTACHMENT_EXTENSIONS_V1,
            (
                AttachmentExtension.PDF,
                AttachmentExtension.JPG,
                AttachmentExtension.JPEG,
                AttachmentExtension.PNG,
            ),
        )

    def test_validated_profile_is_inert_and_non_authorizing(self) -> None:
        validated = validate_attachment_admission_profile_v1(
            expected_attachment_admission_profile_v1()
        )
        self.assertFalse(validated.inspects_file_bytes)
        self.assertFalse(validated.parses_file_format)
        self.assertFalse(validated.creates_sandbox_job)
        self.assertFalse(validated.persists_original_bytes)
        self.assertFalse(validated.persists_original_filename)
        self.assertFalse(validated.logs_request_material)
        self.assertFalse(validated.authorizes_upload)
        self.assertFalse(
            validated.profile.filename_profile.filename_is_storage_input
        )
        self.assertFalse(validated.profile.filename_profile.filename_is_loggable)
        self.assertFalse(
            validated.profile.filename_profile.filename_is_authoritative_kind
        )
        self.assertFalse(
            validated.profile.trust_profile.client_content_type_trusted
        )
        self.assertFalse(validated.profile.trust_profile.magic_bytes_sufficient)
        for field_name in (
            "file_bytes",
            "filename",
            "content_type",
            "path",
            "metadata",
            "sandbox_handle",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class AttachmentAdmissionValidationTests(SimpleTestCase):
    def test_profile_rejects_changed_version_count_and_size(self) -> None:
        valid = expected_attachment_admission_profile_v1()
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(
                valid,
                count_limits=replace(
                    valid.count_limits,
                    total_slots_max=ATTACHMENT_TOTAL_SLOTS_MAX + 1,
                ),
            ),
            replace(
                valid,
                byte_limits=AttachmentByteLimitProfileV1(
                    file_min_bytes=0,
                    file_max_bytes=ATTACHMENT_FILE_MAX_BYTES,
                ),
            ),
            replace(
                valid,
                byte_limits=replace(
                    valid.byte_limits,
                    file_max_bytes=ATTACHMENT_FILE_MAX_BYTES + 1,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(AttachmentAdmissionDescriptorRejected):
                    validate_attachment_admission_profile_v1(candidate)

    def test_profile_rejects_changed_kind_slot_extension_or_filename_policy(
        self,
    ) -> None:
        valid = expected_attachment_admission_profile_v1()
        for candidate in (
            replace(
                valid,
                kind_profile=replace(
                    valid.kind_profile,
                    allowed_kinds=tuple(reversed(ATTACHMENT_KINDS_V1)),
                ),
            ),
            replace(
                valid,
                kind_profile=replace(
                    valid.kind_profile,
                    allowed_slots=valid.kind_profile.allowed_slots[:-1],
                ),
            ),
            replace(
                valid,
                filename_profile=AttachmentFilenameProfileV1(
                    filename_pattern=r".*",
                    stem_min_length=ATTACHMENT_FILENAME_MIN_STEM_LENGTH,
                    stem_max_length=ATTACHMENT_FILENAME_MAX_STEM_LENGTH,
                    filename_is_storage_input=False,
                    filename_is_loggable=False,
                    filename_is_authoritative_kind=False,
                ),
            ),
            replace(
                valid,
                filename_profile=replace(
                    valid.filename_profile,
                    filename_is_storage_input=True,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(AttachmentAdmissionDescriptorRejected):
                    validate_attachment_admission_profile_v1(candidate)

    def test_profile_rejects_trusting_client_or_partial_success(self) -> None:
        valid = expected_attachment_admission_profile_v1()
        for trust_profile in (
            replace(valid.trust_profile, client_content_type_trusted=True),
            replace(valid.trust_profile, content_disposition_trusted=True),
            replace(valid.trust_profile, path_trusted=True),
            replace(valid.trust_profile, extension_trusted=True),
            replace(valid.trust_profile, magic_bytes_sufficient=True),
            replace(valid.trust_profile, parser_warning_accepted=True),
            replace(valid.trust_profile, partial_success_accepted=True),
            AttachmentTrustProfileV1(
                client_content_type_trusted=False,
                content_disposition_trusted=False,
                path_trusted=False,
                extension_trusted=False,
                magic_bytes_sufficient=False,
                parser_warning_accepted=False,
                partial_success_accepted=False,
            ),
        ):
            with self.subTest(trust_profile=trust_profile):
                candidate = replace(valid, trust_profile=trust_profile)
                if trust_profile == valid.trust_profile:
                    self.assertEqual(
                        validate_attachment_admission_profile_v1(
                            candidate
                        ).profile,
                        candidate,
                    )
                else:
                    with self.assertRaises(
                        AttachmentAdmissionDescriptorRejected
                    ):
                        validate_attachment_admission_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        profile = expected_attachment_admission_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        validated = validate_attachment_admission_profile_v1(profile)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.authorizes_upload = True

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "ATTACHMENT_SENTINEL"
        valid = expected_attachment_admission_profile_v1()
        with self.assertRaises(AttachmentAdmissionDescriptorRejected) as raised:
            validate_attachment_admission_profile_v1(
                replace(valid, filename_profile=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "attachment_admission_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
