"""Inert original-report plaintext-frame descriptors for v1.

This module validates only ordered frame-layout metadata. It does not accept
plaintext bytes, canonicalize text, construct frames, parse frames, validate
padding bytes, inspect attachments, encrypt, decrypt, persist content, or
authorize submission.
"""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Never

from .errors import ReportFrameDescriptorRejected
from .report_crypto_descriptors import (
    REPORT_ATTACHMENT_MAX_BYTES,
    REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
    REPORT_CRYPTO_PROTOCOL_VERSION,
    REPORT_MAX_UTF8_BYTES,
    REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
)


REPORT_FRAME_VERSION_BYTE = 0x01
REPORT_FRAME_VERSION_FIELD_BYTES = 1
REPORT_TEXT_LENGTH_FIELD_BYTES = 4
REPORT_ATTACHMENT_KIND_FIELD_BYTES = 1
REPORT_ATTACHMENT_LENGTH_FIELD_BYTES = 8
REPORT_TEXT_FRAME_HEADER_BYTES = (
    REPORT_FRAME_VERSION_FIELD_BYTES + REPORT_TEXT_LENGTH_FIELD_BYTES
)
REPORT_ATTACHMENT_FRAME_HEADER_BYTES = (
    REPORT_FRAME_VERSION_FIELD_BYTES
    + REPORT_ATTACHMENT_KIND_FIELD_BYTES
    + REPORT_ATTACHMENT_LENGTH_FIELD_BYTES
)
REPORT_TEXT_PADDING_REQUIRED = True
REPORT_ATTACHMENT_PADDING_REQUIRED = True


class ReportFrameKind(StrEnum):
    REPORT_TEXT = "REPORT_TEXT"
    ATTACHMENT = "ATTACHMENT"


class ReportFrameFieldType(StrEnum):
    VERSION_BYTE = "VERSION_BYTE"
    OBJECT_KIND_CODE = "OBJECT_KIND_CODE"
    UINT32_BIG_ENDIAN = "UINT32_BIG_ENDIAN"
    UINT64_BIG_ENDIAN = "UINT64_BIG_ENDIAN"
    CANONICAL_UTF8_TEXT = "CANONICAL_UTF8_TEXT"
    ACCEPTED_ORIGINAL_BYTES = "ACCEPTED_ORIGINAL_BYTES"
    ZERO_PADDING = "ZERO_PADDING"


class ReportAttachmentKindCode(IntEnum):
    PDF = 0x01
    JPEG = 0x02
    PNG = 0x03


REPORT_ATTACHMENT_KIND_CODES_V1 = (
    ReportAttachmentKindCode.PDF,
    ReportAttachmentKindCode.JPEG,
    ReportAttachmentKindCode.PNG,
)


@dataclass(frozen=True, slots=True)
class ReportFrameFieldV1:
    name: str
    field_type: ReportFrameFieldType
    size_bytes: int | None
    exact_value: int | str | None
    max_payload_bytes: int | None


@dataclass(frozen=True, slots=True)
class ReportPlaintextFrameLayoutV1:
    scheme_version: int
    frame_kind: ReportFrameKind
    total_size_bytes: int
    fields: tuple[ReportFrameFieldV1, ...]
    zero_padding_required: bool


@dataclass(frozen=True, slots=True)
class StructurallyValidReportFrameProfileV1:
    text_frame_layout: ReportPlaintextFrameLayoutV1
    attachment_frame_layout: ReportPlaintextFrameLayoutV1
    attachment_kind_codes: tuple[ReportAttachmentKindCode, ...]

    @property
    def accepts_plaintext(self) -> bool:
        return False

    @property
    def constructs_frame(self) -> bool:
        return False

    @property
    def parses_frame(self) -> bool:
        return False

    @property
    def validates_padding_bytes(self) -> bool:
        return False

    @property
    def inspects_attachment_bytes(self) -> bool:
        return False

    @property
    def encrypts_frame(self) -> bool:
        return False

    @property
    def persists_frame(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


REPORT_TEXT_FRAME_FIELDS_V1 = (
    ReportFrameFieldV1(
        "version",
        ReportFrameFieldType.VERSION_BYTE,
        REPORT_FRAME_VERSION_FIELD_BYTES,
        REPORT_FRAME_VERSION_BYTE,
        None,
    ),
    ReportFrameFieldV1(
        "utf8_byte_length",
        ReportFrameFieldType.UINT32_BIG_ENDIAN,
        REPORT_TEXT_LENGTH_FIELD_BYTES,
        None,
        REPORT_MAX_UTF8_BYTES,
    ),
    ReportFrameFieldV1(
        "canonical_utf8_report_text",
        ReportFrameFieldType.CANONICAL_UTF8_TEXT,
        None,
        None,
        REPORT_MAX_UTF8_BYTES,
    ),
    ReportFrameFieldV1(
        "zero_padding",
        ReportFrameFieldType.ZERO_PADDING,
        None,
        0,
        None,
    ),
)

REPORT_ATTACHMENT_FRAME_FIELDS_V1 = (
    ReportFrameFieldV1(
        "version",
        ReportFrameFieldType.VERSION_BYTE,
        REPORT_FRAME_VERSION_FIELD_BYTES,
        REPORT_FRAME_VERSION_BYTE,
        None,
    ),
    ReportFrameFieldV1(
        "object_kind_code",
        ReportFrameFieldType.OBJECT_KIND_CODE,
        REPORT_ATTACHMENT_KIND_FIELD_BYTES,
        None,
        None,
    ),
    ReportFrameFieldV1(
        "original_byte_length",
        ReportFrameFieldType.UINT64_BIG_ENDIAN,
        REPORT_ATTACHMENT_LENGTH_FIELD_BYTES,
        None,
        REPORT_ATTACHMENT_MAX_BYTES,
    ),
    ReportFrameFieldV1(
        "accepted_original_bytes",
        ReportFrameFieldType.ACCEPTED_ORIGINAL_BYTES,
        None,
        None,
        REPORT_ATTACHMENT_MAX_BYTES,
    ),
    ReportFrameFieldV1(
        "zero_padding",
        ReportFrameFieldType.ZERO_PADDING,
        None,
        0,
        None,
    ),
)


def _reject() -> Never:
    raise ReportFrameDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_frame_kind(
    value: object,
    *,
    expected: ReportFrameKind,
) -> ReportFrameKind:
    if isinstance(value, ReportFrameKind):
        if value == expected:
            return value
        _reject()
    if type(value) is str and value == expected.value:
        return expected
    _reject()


def _require_field_type(value: object) -> ReportFrameFieldType:
    if isinstance(value, ReportFrameFieldType):
        return value
    if type(value) is str:
        for field_type in ReportFrameFieldType:
            if value == field_type.value:
                return field_type
    _reject()


def _normalize_field(field: ReportFrameFieldV1) -> ReportFrameFieldV1:
    if type(field) is not ReportFrameFieldV1:
        _reject()
    if type(field.name) is not str:
        _reject()
    if field.size_bytes is not None:
        if type(field.size_bytes) is not int or field.size_bytes <= 0:
            _reject()
    if field.exact_value is not None:
        if type(field.exact_value) not in (int, str):
            _reject()
    if field.max_payload_bytes is not None:
        if type(field.max_payload_bytes) is not int or field.max_payload_bytes < 0:
            _reject()
    return ReportFrameFieldV1(
        name=field.name,
        field_type=_require_field_type(field.field_type),
        size_bytes=field.size_bytes,
        exact_value=field.exact_value,
        max_payload_bytes=field.max_payload_bytes,
    )


def _require_fields_exact(
    value: object,
    *,
    expected: tuple[ReportFrameFieldV1, ...],
) -> tuple[ReportFrameFieldV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_normalize_field(field) for field in value)
    if normalized != expected:
        _reject()
    return normalized


def _require_attachment_kind_code(
    value: object,
) -> ReportAttachmentKindCode:
    if isinstance(value, ReportAttachmentKindCode):
        return value
    _reject()


def _require_attachment_kind_codes(
    value: object,
) -> tuple[ReportAttachmentKindCode, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_attachment_kind_code(item) for item in value)
    if normalized != REPORT_ATTACHMENT_KIND_CODES_V1:
        _reject()
    return normalized


def validate_report_text_frame_layout_v1(
    layout: ReportPlaintextFrameLayoutV1,
) -> ReportPlaintextFrameLayoutV1:
    if type(layout) is not ReportPlaintextFrameLayoutV1:
        _reject()
    return ReportPlaintextFrameLayoutV1(
        scheme_version=_require_uint_exact(
            layout.scheme_version,
            expected=REPORT_CRYPTO_PROTOCOL_VERSION,
        ),
        frame_kind=_require_frame_kind(
            layout.frame_kind,
            expected=ReportFrameKind.REPORT_TEXT,
        ),
        total_size_bytes=_require_uint_exact(
            layout.total_size_bytes,
            expected=REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
        ),
        fields=_require_fields_exact(
            layout.fields,
            expected=REPORT_TEXT_FRAME_FIELDS_V1,
        ),
        zero_padding_required=_require_bool_exact(
            layout.zero_padding_required,
            expected=REPORT_TEXT_PADDING_REQUIRED,
        ),
    )


def validate_report_attachment_frame_layout_v1(
    layout: ReportPlaintextFrameLayoutV1,
) -> ReportPlaintextFrameLayoutV1:
    if type(layout) is not ReportPlaintextFrameLayoutV1:
        _reject()
    return ReportPlaintextFrameLayoutV1(
        scheme_version=_require_uint_exact(
            layout.scheme_version,
            expected=REPORT_CRYPTO_PROTOCOL_VERSION,
        ),
        frame_kind=_require_frame_kind(
            layout.frame_kind,
            expected=ReportFrameKind.ATTACHMENT,
        ),
        total_size_bytes=_require_uint_exact(
            layout.total_size_bytes,
            expected=REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
        ),
        fields=_require_fields_exact(
            layout.fields,
            expected=REPORT_ATTACHMENT_FRAME_FIELDS_V1,
        ),
        zero_padding_required=_require_bool_exact(
            layout.zero_padding_required,
            expected=REPORT_ATTACHMENT_PADDING_REQUIRED,
        ),
    )


def validate_report_frame_profile_v1(
    *,
    text_frame_layout: ReportPlaintextFrameLayoutV1,
    attachment_frame_layout: ReportPlaintextFrameLayoutV1,
    attachment_kind_codes: tuple[ReportAttachmentKindCode, ...],
) -> StructurallyValidReportFrameProfileV1:
    """Validate only exact v1 frame metadata; never handle frame bytes."""

    return StructurallyValidReportFrameProfileV1(
        text_frame_layout=validate_report_text_frame_layout_v1(
            text_frame_layout
        ),
        attachment_frame_layout=validate_report_attachment_frame_layout_v1(
            attachment_frame_layout
        ),
        attachment_kind_codes=_require_attachment_kind_codes(
            attachment_kind_codes
        ),
    )


def expected_report_frame_profile_v1() -> StructurallyValidReportFrameProfileV1:
    """Return the exact inert plaintext-frame layout profile."""

    return validate_report_frame_profile_v1(
        text_frame_layout=ReportPlaintextFrameLayoutV1(
            scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
            frame_kind=ReportFrameKind.REPORT_TEXT,
            total_size_bytes=REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
            fields=REPORT_TEXT_FRAME_FIELDS_V1,
            zero_padding_required=REPORT_TEXT_PADDING_REQUIRED,
        ),
        attachment_frame_layout=ReportPlaintextFrameLayoutV1(
            scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
            frame_kind=ReportFrameKind.ATTACHMENT,
            total_size_bytes=REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
            fields=REPORT_ATTACHMENT_FRAME_FIELDS_V1,
            zero_padding_required=REPORT_ATTACHMENT_PADDING_REQUIRED,
        ),
        attachment_kind_codes=REPORT_ATTACHMENT_KIND_CODES_V1,
    )
