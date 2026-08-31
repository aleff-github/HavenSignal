"""Negative tests for inert request and multipart admission descriptors."""

from dataclasses import FrozenInstanceError, replace

from django.test import SimpleTestCase

from security_interfaces import (
    REQUEST_ADMISSION_CONTENT_TYPES_V1,
    REQUEST_ADMISSION_METHODS_V1,
    REQUEST_ADMISSION_PROTOCOL_VERSION,
    REQUEST_BODY_ABSOLUTE_TIMEOUT_SECONDS,
    REQUEST_BODY_IDLE_TIMEOUT_SECONDS,
    REQUEST_BODY_MAX_BYTES,
    REQUEST_BOUNDARY_MAX_LENGTH,
    REQUEST_BOUNDARY_MIN_LENGTH,
    REQUEST_CONTROL_FIELDS_TOTAL_MAX_BYTES,
    REQUEST_CONTROL_FIELD_MAX_BYTES,
    REQUEST_FILE_PARTS_MAX,
    REQUEST_FILE_PARTS_TOTAL_MAX_BYTES,
    REQUEST_FILE_PART_MAX_BYTES,
    REQUEST_FILE_SLOTS_V1,
    REQUEST_HEADER_COMPLETION_TIMEOUT_SECONDS,
    REQUEST_IN_FLIGHT_PLAINTEXT_MAX_BYTES,
    REQUEST_MULTIPART_PARTS_MAX,
    REQUEST_PART_HEADER_FIELDS_MAX,
    REQUEST_PART_HEADER_SECTIONS_TOTAL_MAX_BYTES,
    REQUEST_PART_HEADER_SECTION_MAX_BYTES,
    REQUEST_REPORT_TEXT_MAX_SCALAR_VALUES,
    REQUEST_REPORT_TEXT_MAX_UTF8_BYTES,
    REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES,
    RequestAdmissionContentType,
    RequestAdmissionDescriptorRejected,
    RequestAdmissionMethod,
    RequestFileSlot,
    RequestOuterBodyLimitProfileV1,
    RequestStreamingLimitProfileV1,
    expected_request_admission_protocol_profile_v1,
    validate_request_admission_protocol_profile_v1,
)


class RequestAdmissionDescriptorProfileTests(SimpleTestCase):
    def test_constants_match_the_approved_v1_profile(self) -> None:
        self.assertEqual(REQUEST_ADMISSION_PROTOCOL_VERSION, 1)
        self.assertEqual(REQUEST_BODY_MAX_BYTES, 22_020_096)
        self.assertEqual(REQUEST_FILE_PART_MAX_BYTES, 5_242_880)
        self.assertEqual(REQUEST_FILE_PARTS_TOTAL_MAX_BYTES, 20_971_520)
        self.assertEqual(REQUEST_REPORT_TEXT_MAX_SCALAR_VALUES, 5_000)
        self.assertEqual(REQUEST_REPORT_TEXT_MAX_UTF8_BYTES, 20_000)
        self.assertEqual(REQUEST_MULTIPART_PARTS_MAX, 12)
        self.assertEqual(REQUEST_FILE_PARTS_MAX, 4)
        self.assertEqual(REQUEST_CONTROL_FIELD_MAX_BYTES, 4_096)
        self.assertEqual(REQUEST_CONTROL_FIELDS_TOTAL_MAX_BYTES, 32_768)
        self.assertEqual(REQUEST_PART_HEADER_SECTION_MAX_BYTES, 4_096)
        self.assertEqual(REQUEST_PART_HEADER_SECTIONS_TOTAL_MAX_BYTES, 32_768)
        self.assertEqual(REQUEST_PART_HEADER_FIELDS_MAX, 4)
        self.assertEqual(REQUEST_BOUNDARY_MIN_LENGTH, 16)
        self.assertEqual(REQUEST_BOUNDARY_MAX_LENGTH, 70)
        self.assertEqual(REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES, 65_536)
        self.assertEqual(REQUEST_IN_FLIGHT_PLAINTEXT_MAX_BYTES, 262_144)
        self.assertEqual(REQUEST_HEADER_COMPLETION_TIMEOUT_SECONDS, 10)
        self.assertEqual(REQUEST_BODY_IDLE_TIMEOUT_SECONDS, 15)
        self.assertEqual(REQUEST_BODY_ABSOLUTE_TIMEOUT_SECONDS, 300)

    def test_method_content_type_and_file_slot_registries_are_closed(self) -> None:
        self.assertEqual(
            REQUEST_ADMISSION_METHODS_V1,
            (RequestAdmissionMethod.POST,),
        )
        self.assertEqual(
            REQUEST_ADMISSION_CONTENT_TYPES_V1,
            (RequestAdmissionContentType.MULTIPART_FORM_DATA,),
        )
        self.assertEqual(
            REQUEST_FILE_SLOTS_V1,
            (
                RequestFileSlot.PDF,
                RequestFileSlot.IMAGE_1,
                RequestFileSlot.IMAGE_2,
                RequestFileSlot.IMAGE_3,
            ),
        )

    def test_validated_profile_is_inert_and_non_authorizing(self) -> None:
        validated = validate_request_admission_protocol_profile_v1(
            expected_request_admission_protocol_profile_v1()
        )
        self.assertFalse(validated.parses_http)
        self.assertFalse(validated.parses_multipart)
        self.assertFalse(validated.installs_upload_handler)
        self.assertFalse(validated.reads_file_bytes)
        self.assertFalse(validated.exposes_original_filename)
        self.assertFalse(validated.creates_sandbox_job)
        self.assertFalse(validated.persists_plaintext)
        self.assertFalse(validated.accepts_submission)
        self.assertFalse(
            validated
            .profile
            .streaming_limits
            .default_django_memory_handler_allowed
        )
        self.assertFalse(
            validated
            .profile
            .streaming_limits
            .default_django_temporary_handler_allowed
        )
        self.assertFalse(
            validated.profile.streaming_limits.request_body_disk_spooling_allowed
        )
        for field_name in (
            "request",
            "body",
            "parts",
            "file_bytes",
            "filename",
            "headers",
            "cookies",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RequestAdmissionDescriptorValidationTests(SimpleTestCase):
    def test_profile_rejects_changed_outer_limits_and_unsafe_framing(self) -> None:
        valid = expected_request_admission_protocol_profile_v1()
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(
                valid,
                outer_body_limits=replace(
                    valid.outer_body_limits,
                    complete_body_max_bytes=REQUEST_BODY_MAX_BYTES + 1,
                ),
            ),
            replace(
                valid,
                outer_body_limits=RequestOuterBodyLimitProfileV1(
                    complete_body_max_bytes=REQUEST_BODY_MAX_BYTES,
                    content_length_required=False,
                    transfer_coding_allowed=False,
                    content_encoding_allowed=False,
                ),
            ),
            replace(
                valid,
                outer_body_limits=replace(
                    valid.outer_body_limits,
                    transfer_coding_allowed=True,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RequestAdmissionDescriptorRejected):
                    validate_request_admission_protocol_profile_v1(candidate)

    def test_profile_rejects_changed_multipart_limits_and_file_order(self) -> None:
        valid = expected_request_admission_protocol_profile_v1()
        for candidate in (
            replace(
                valid,
                multipart_limits=replace(
                    valid.multipart_limits,
                    file_part_max_bytes=REQUEST_FILE_PART_MAX_BYTES + 1,
                ),
            ),
            replace(
                valid,
                multipart_limits=replace(
                    valid.multipart_limits,
                    boundary_min_length=REQUEST_BOUNDARY_MIN_LENGTH - 1,
                ),
            ),
            replace(
                valid,
                grammar_profile=replace(
                    valid.grammar_profile,
                    file_slots=tuple(reversed(REQUEST_FILE_SLOTS_V1)),
                ),
            ),
            replace(
                valid,
                grammar_profile=replace(
                    valid.grammar_profile,
                    unknown_fields_allowed=True,
                ),
            ),
            replace(
                valid,
                grammar_profile=replace(
                    valid.grammar_profile,
                    allowed_methods=("GET",),
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RequestAdmissionDescriptorRejected):
                    validate_request_admission_protocol_profile_v1(candidate)

    def test_profile_rejects_buffering_time_and_django_handler_weakening(
        self,
    ) -> None:
        valid = expected_request_admission_protocol_profile_v1()
        for candidate in (
            replace(
                valid,
                streaming_limits=replace(
                    valid.streaming_limits,
                    retained_chunk_max_bytes=(
                        REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES + 1
                    ),
                ),
            ),
            replace(
                valid,
                streaming_limits=RequestStreamingLimitProfileV1(
                    retained_chunk_max_bytes=(
                        REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES
                    ),
                    in_flight_plaintext_max_bytes=(
                        REQUEST_IN_FLIGHT_PLAINTEXT_MAX_BYTES
                    ),
                    default_django_memory_handler_allowed=True,
                    default_django_temporary_handler_allowed=False,
                    request_body_disk_spooling_allowed=False,
                ),
            ),
            replace(
                valid,
                timing_profile=replace(
                    valid.timing_profile,
                    body_absolute_timeout_seconds=(
                        REQUEST_BODY_ABSOLUTE_TIMEOUT_SECONDS + 1
                    ),
                ),
            ),
            replace(
                valid,
                timing_profile=replace(
                    valid.timing_profile,
                    deadlines_use_client_time=True,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RequestAdmissionDescriptorRejected):
                    validate_request_admission_protocol_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        profile = expected_request_admission_protocol_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        validated = validate_request_admission_protocol_profile_v1(profile)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.accepts_submission = True

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "REQUEST_ADMISSION_SENTINEL"
        valid = expected_request_admission_protocol_profile_v1()
        with self.assertRaises(RequestAdmissionDescriptorRejected) as raised:
            validate_request_admission_protocol_profile_v1(
                replace(valid, grammar_profile=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "request_admission_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
