"""Inert request and multipart admission descriptors for v1.

This module validates only static request-limit metadata. It does not parse HTTP
or multipart bodies, install Django upload handlers, read files, create sandbox
jobs, persist data, log request material, or authorize a submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RequestAdmissionDescriptorRejected


REQUEST_ADMISSION_PROTOCOL_VERSION = 1
REQUEST_BODY_MAX_BYTES = 22_020_096
REQUEST_FILE_PART_MAX_BYTES = 5_242_880
REQUEST_FILE_PARTS_TOTAL_MAX_BYTES = 20_971_520
REQUEST_REPORT_TEXT_MAX_SCALAR_VALUES = 5_000
REQUEST_REPORT_TEXT_MAX_UTF8_BYTES = 20_000
REQUEST_MULTIPART_PARTS_MAX = 12
REQUEST_FILE_PARTS_MAX = 4
REQUEST_CONTROL_FIELD_MAX_BYTES = 4_096
REQUEST_CONTROL_FIELDS_TOTAL_MAX_BYTES = 32_768
REQUEST_PART_HEADER_SECTION_MAX_BYTES = 4_096
REQUEST_PART_HEADER_SECTIONS_TOTAL_MAX_BYTES = 32_768
REQUEST_PART_HEADER_FIELDS_MAX = 4
REQUEST_BOUNDARY_MIN_LENGTH = 16
REQUEST_BOUNDARY_MAX_LENGTH = 70
REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES = 65_536
REQUEST_IN_FLIGHT_PLAINTEXT_MAX_BYTES = 262_144
REQUEST_HEADER_COMPLETION_TIMEOUT_SECONDS = 10
REQUEST_BODY_IDLE_TIMEOUT_SECONDS = 15
REQUEST_BODY_ABSOLUTE_TIMEOUT_SECONDS = 300


class RequestAdmissionMethod(StrEnum):
    POST = "POST"


class RequestAdmissionContentType(StrEnum):
    MULTIPART_FORM_DATA = "multipart/form-data"


class RequestFileSlot(StrEnum):
    PDF = "PDF"
    IMAGE_1 = "IMAGE_1"
    IMAGE_2 = "IMAGE_2"
    IMAGE_3 = "IMAGE_3"


REQUEST_ADMISSION_METHODS_V1 = (RequestAdmissionMethod.POST,)
REQUEST_ADMISSION_CONTENT_TYPES_V1 = (
    RequestAdmissionContentType.MULTIPART_FORM_DATA,
)
REQUEST_FILE_SLOTS_V1 = (
    RequestFileSlot.PDF,
    RequestFileSlot.IMAGE_1,
    RequestFileSlot.IMAGE_2,
    RequestFileSlot.IMAGE_3,
)


@dataclass(frozen=True, slots=True)
class RequestOuterBodyLimitProfileV1:
    complete_body_max_bytes: int
    content_length_required: bool
    transfer_coding_allowed: bool
    content_encoding_allowed: bool


@dataclass(frozen=True, slots=True)
class RequestMultipartLimitProfileV1:
    multipart_parts_max: int
    file_parts_max: int
    file_part_max_bytes: int
    file_parts_total_max_bytes: int
    control_field_max_bytes: int
    control_fields_total_max_bytes: int
    part_header_section_max_bytes: int
    part_header_sections_total_max_bytes: int
    part_header_fields_max: int
    boundary_min_length: int
    boundary_max_length: int


@dataclass(frozen=True, slots=True)
class RequestReportTextLimitProfileV1:
    max_scalar_values: int
    max_utf8_bytes: int


@dataclass(frozen=True, slots=True)
class RequestStreamingLimitProfileV1:
    retained_chunk_max_bytes: int
    in_flight_plaintext_max_bytes: int
    default_django_memory_handler_allowed: bool
    default_django_temporary_handler_allowed: bool
    request_body_disk_spooling_allowed: bool


@dataclass(frozen=True, slots=True)
class RequestTimingProfileV1:
    header_completion_timeout_seconds: int
    body_idle_timeout_seconds: int
    body_absolute_timeout_seconds: int
    deadlines_use_client_time: bool


@dataclass(frozen=True, slots=True)
class RequestGrammarProfileV1:
    allowed_methods: tuple[RequestAdmissionMethod, ...]
    allowed_content_types: tuple[RequestAdmissionContentType, ...]
    file_slots: tuple[RequestFileSlot, ...]
    duplicate_fields_allowed: bool
    unknown_fields_allowed: bool
    nested_multipart_allowed: bool
    filename_star_allowed: bool
    content_transfer_encoding_allowed: bool


@dataclass(frozen=True, slots=True)
class RequestAdmissionProtocolProfileV1:
    scheme_version: int
    outer_body_limits: RequestOuterBodyLimitProfileV1
    multipart_limits: RequestMultipartLimitProfileV1
    report_text_limits: RequestReportTextLimitProfileV1
    streaming_limits: RequestStreamingLimitProfileV1
    timing_profile: RequestTimingProfileV1
    grammar_profile: RequestGrammarProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRequestAdmissionProfileV1:
    profile: RequestAdmissionProtocolProfileV1

    @property
    def parses_http(self) -> bool:
        return False

    @property
    def parses_multipart(self) -> bool:
        return False

    @property
    def installs_upload_handler(self) -> bool:
        return False

    @property
    def reads_file_bytes(self) -> bool:
        return False

    @property
    def exposes_original_filename(self) -> bool:
        return False

    @property
    def creates_sandbox_job(self) -> bool:
        return False

    @property
    def persists_plaintext(self) -> bool:
        return False

    @property
    def accepts_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise RequestAdmissionDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_method(value: object) -> RequestAdmissionMethod:
    if isinstance(value, RequestAdmissionMethod):
        return value
    if type(value) is str:
        for method in RequestAdmissionMethod:
            if value == method.value:
                return method
    _reject()


def _require_content_type(value: object) -> RequestAdmissionContentType:
    if isinstance(value, RequestAdmissionContentType):
        return value
    if type(value) is str:
        for content_type in RequestAdmissionContentType:
            if value == content_type.value:
                return content_type
    _reject()


def _require_file_slot(value: object) -> RequestFileSlot:
    if isinstance(value, RequestFileSlot):
        return value
    if type(value) is str:
        for slot in RequestFileSlot:
            if value == slot.value:
                return slot
    _reject()


def _require_methods(
    value: object,
) -> tuple[RequestAdmissionMethod, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_method(method) for method in value)
    if normalized != REQUEST_ADMISSION_METHODS_V1:
        _reject()
    return normalized


def _require_content_types(
    value: object,
) -> tuple[RequestAdmissionContentType, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_content_type(content_type) for content_type in value
    )
    if normalized != REQUEST_ADMISSION_CONTENT_TYPES_V1:
        _reject()
    return normalized


def _require_file_slots(value: object) -> tuple[RequestFileSlot, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_file_slot(slot) for slot in value)
    if normalized != REQUEST_FILE_SLOTS_V1:
        _reject()
    return normalized


def validate_request_outer_body_limit_profile_v1(
    profile: RequestOuterBodyLimitProfileV1,
) -> RequestOuterBodyLimitProfileV1:
    if type(profile) is not RequestOuterBodyLimitProfileV1:
        _reject()
    return RequestOuterBodyLimitProfileV1(
        complete_body_max_bytes=_require_uint_exact(
            profile.complete_body_max_bytes,
            expected=REQUEST_BODY_MAX_BYTES,
        ),
        content_length_required=_require_bool_exact(
            profile.content_length_required,
            expected=True,
        ),
        transfer_coding_allowed=_require_bool_exact(
            profile.transfer_coding_allowed,
            expected=False,
        ),
        content_encoding_allowed=_require_bool_exact(
            profile.content_encoding_allowed,
            expected=False,
        ),
    )


def validate_request_multipart_limit_profile_v1(
    profile: RequestMultipartLimitProfileV1,
) -> RequestMultipartLimitProfileV1:
    if type(profile) is not RequestMultipartLimitProfileV1:
        _reject()
    return RequestMultipartLimitProfileV1(
        multipart_parts_max=_require_uint_exact(
            profile.multipart_parts_max,
            expected=REQUEST_MULTIPART_PARTS_MAX,
        ),
        file_parts_max=_require_uint_exact(
            profile.file_parts_max,
            expected=REQUEST_FILE_PARTS_MAX,
        ),
        file_part_max_bytes=_require_uint_exact(
            profile.file_part_max_bytes,
            expected=REQUEST_FILE_PART_MAX_BYTES,
        ),
        file_parts_total_max_bytes=_require_uint_exact(
            profile.file_parts_total_max_bytes,
            expected=REQUEST_FILE_PARTS_TOTAL_MAX_BYTES,
        ),
        control_field_max_bytes=_require_uint_exact(
            profile.control_field_max_bytes,
            expected=REQUEST_CONTROL_FIELD_MAX_BYTES,
        ),
        control_fields_total_max_bytes=_require_uint_exact(
            profile.control_fields_total_max_bytes,
            expected=REQUEST_CONTROL_FIELDS_TOTAL_MAX_BYTES,
        ),
        part_header_section_max_bytes=_require_uint_exact(
            profile.part_header_section_max_bytes,
            expected=REQUEST_PART_HEADER_SECTION_MAX_BYTES,
        ),
        part_header_sections_total_max_bytes=_require_uint_exact(
            profile.part_header_sections_total_max_bytes,
            expected=REQUEST_PART_HEADER_SECTIONS_TOTAL_MAX_BYTES,
        ),
        part_header_fields_max=_require_uint_exact(
            profile.part_header_fields_max,
            expected=REQUEST_PART_HEADER_FIELDS_MAX,
        ),
        boundary_min_length=_require_uint_exact(
            profile.boundary_min_length,
            expected=REQUEST_BOUNDARY_MIN_LENGTH,
        ),
        boundary_max_length=_require_uint_exact(
            profile.boundary_max_length,
            expected=REQUEST_BOUNDARY_MAX_LENGTH,
        ),
    )


def validate_request_report_text_limit_profile_v1(
    profile: RequestReportTextLimitProfileV1,
) -> RequestReportTextLimitProfileV1:
    if type(profile) is not RequestReportTextLimitProfileV1:
        _reject()
    return RequestReportTextLimitProfileV1(
        max_scalar_values=_require_uint_exact(
            profile.max_scalar_values,
            expected=REQUEST_REPORT_TEXT_MAX_SCALAR_VALUES,
        ),
        max_utf8_bytes=_require_uint_exact(
            profile.max_utf8_bytes,
            expected=REQUEST_REPORT_TEXT_MAX_UTF8_BYTES,
        ),
    )


def validate_request_streaming_limit_profile_v1(
    profile: RequestStreamingLimitProfileV1,
) -> RequestStreamingLimitProfileV1:
    if type(profile) is not RequestStreamingLimitProfileV1:
        _reject()
    return RequestStreamingLimitProfileV1(
        retained_chunk_max_bytes=_require_uint_exact(
            profile.retained_chunk_max_bytes,
            expected=REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES,
        ),
        in_flight_plaintext_max_bytes=_require_uint_exact(
            profile.in_flight_plaintext_max_bytes,
            expected=REQUEST_IN_FLIGHT_PLAINTEXT_MAX_BYTES,
        ),
        default_django_memory_handler_allowed=_require_bool_exact(
            profile.default_django_memory_handler_allowed,
            expected=False,
        ),
        default_django_temporary_handler_allowed=_require_bool_exact(
            profile.default_django_temporary_handler_allowed,
            expected=False,
        ),
        request_body_disk_spooling_allowed=_require_bool_exact(
            profile.request_body_disk_spooling_allowed,
            expected=False,
        ),
    )


def validate_request_timing_profile_v1(
    profile: RequestTimingProfileV1,
) -> RequestTimingProfileV1:
    if type(profile) is not RequestTimingProfileV1:
        _reject()
    return RequestTimingProfileV1(
        header_completion_timeout_seconds=_require_uint_exact(
            profile.header_completion_timeout_seconds,
            expected=REQUEST_HEADER_COMPLETION_TIMEOUT_SECONDS,
        ),
        body_idle_timeout_seconds=_require_uint_exact(
            profile.body_idle_timeout_seconds,
            expected=REQUEST_BODY_IDLE_TIMEOUT_SECONDS,
        ),
        body_absolute_timeout_seconds=_require_uint_exact(
            profile.body_absolute_timeout_seconds,
            expected=REQUEST_BODY_ABSOLUTE_TIMEOUT_SECONDS,
        ),
        deadlines_use_client_time=_require_bool_exact(
            profile.deadlines_use_client_time,
            expected=False,
        ),
    )


def validate_request_grammar_profile_v1(
    profile: RequestGrammarProfileV1,
) -> RequestGrammarProfileV1:
    if type(profile) is not RequestGrammarProfileV1:
        _reject()
    return RequestGrammarProfileV1(
        allowed_methods=_require_methods(profile.allowed_methods),
        allowed_content_types=_require_content_types(
            profile.allowed_content_types
        ),
        file_slots=_require_file_slots(profile.file_slots),
        duplicate_fields_allowed=_require_bool_exact(
            profile.duplicate_fields_allowed,
            expected=False,
        ),
        unknown_fields_allowed=_require_bool_exact(
            profile.unknown_fields_allowed,
            expected=False,
        ),
        nested_multipart_allowed=_require_bool_exact(
            profile.nested_multipart_allowed,
            expected=False,
        ),
        filename_star_allowed=_require_bool_exact(
            profile.filename_star_allowed,
            expected=False,
        ),
        content_transfer_encoding_allowed=_require_bool_exact(
            profile.content_transfer_encoding_allowed,
            expected=False,
        ),
    )


def validate_request_admission_protocol_profile_v1(
    profile: RequestAdmissionProtocolProfileV1,
) -> StructurallyValidRequestAdmissionProfileV1:
    if type(profile) is not RequestAdmissionProtocolProfileV1:
        _reject()
    normalized = RequestAdmissionProtocolProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=REQUEST_ADMISSION_PROTOCOL_VERSION,
        ),
        outer_body_limits=validate_request_outer_body_limit_profile_v1(
            profile.outer_body_limits
        ),
        multipart_limits=validate_request_multipart_limit_profile_v1(
            profile.multipart_limits
        ),
        report_text_limits=validate_request_report_text_limit_profile_v1(
            profile.report_text_limits
        ),
        streaming_limits=validate_request_streaming_limit_profile_v1(
            profile.streaming_limits
        ),
        timing_profile=validate_request_timing_profile_v1(
            profile.timing_profile
        ),
        grammar_profile=validate_request_grammar_profile_v1(
            profile.grammar_profile
        ),
    )
    return StructurallyValidRequestAdmissionProfileV1(profile=normalized)


def expected_request_admission_protocol_profile_v1(
) -> RequestAdmissionProtocolProfileV1:
    """Return only the approved request-admission metadata."""

    return RequestAdmissionProtocolProfileV1(
        scheme_version=REQUEST_ADMISSION_PROTOCOL_VERSION,
        outer_body_limits=RequestOuterBodyLimitProfileV1(
            complete_body_max_bytes=REQUEST_BODY_MAX_BYTES,
            content_length_required=True,
            transfer_coding_allowed=False,
            content_encoding_allowed=False,
        ),
        multipart_limits=RequestMultipartLimitProfileV1(
            multipart_parts_max=REQUEST_MULTIPART_PARTS_MAX,
            file_parts_max=REQUEST_FILE_PARTS_MAX,
            file_part_max_bytes=REQUEST_FILE_PART_MAX_BYTES,
            file_parts_total_max_bytes=REQUEST_FILE_PARTS_TOTAL_MAX_BYTES,
            control_field_max_bytes=REQUEST_CONTROL_FIELD_MAX_BYTES,
            control_fields_total_max_bytes=REQUEST_CONTROL_FIELDS_TOTAL_MAX_BYTES,
            part_header_section_max_bytes=REQUEST_PART_HEADER_SECTION_MAX_BYTES,
            part_header_sections_total_max_bytes=(
                REQUEST_PART_HEADER_SECTIONS_TOTAL_MAX_BYTES
            ),
            part_header_fields_max=REQUEST_PART_HEADER_FIELDS_MAX,
            boundary_min_length=REQUEST_BOUNDARY_MIN_LENGTH,
            boundary_max_length=REQUEST_BOUNDARY_MAX_LENGTH,
        ),
        report_text_limits=RequestReportTextLimitProfileV1(
            max_scalar_values=REQUEST_REPORT_TEXT_MAX_SCALAR_VALUES,
            max_utf8_bytes=REQUEST_REPORT_TEXT_MAX_UTF8_BYTES,
        ),
        streaming_limits=RequestStreamingLimitProfileV1(
            retained_chunk_max_bytes=REQUEST_STREAMING_CHUNK_RETAINED_MAX_BYTES,
            in_flight_plaintext_max_bytes=REQUEST_IN_FLIGHT_PLAINTEXT_MAX_BYTES,
            default_django_memory_handler_allowed=False,
            default_django_temporary_handler_allowed=False,
            request_body_disk_spooling_allowed=False,
        ),
        timing_profile=RequestTimingProfileV1(
            header_completion_timeout_seconds=(
                REQUEST_HEADER_COMPLETION_TIMEOUT_SECONDS
            ),
            body_idle_timeout_seconds=REQUEST_BODY_IDLE_TIMEOUT_SECONDS,
            body_absolute_timeout_seconds=REQUEST_BODY_ABSOLUTE_TIMEOUT_SECONDS,
            deadlines_use_client_time=False,
        ),
        grammar_profile=RequestGrammarProfileV1(
            allowed_methods=REQUEST_ADMISSION_METHODS_V1,
            allowed_content_types=REQUEST_ADMISSION_CONTENT_TYPES_V1,
            file_slots=REQUEST_FILE_SLOTS_V1,
            duplicate_fields_allowed=False,
            unknown_fields_allowed=False,
            nested_multipart_allowed=False,
            filename_star_allowed=False,
            content_transfer_encoding_allowed=False,
        ),
    )
