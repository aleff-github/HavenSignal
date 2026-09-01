"""Inert original-report AAD/envelope schema descriptors for v1.

This module validates only ordered schema metadata. It does not encode CBOR,
parse envelopes, hold identifiers, hold ciphertext, call services, stream
attachments, or authorize report use.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import ReportSchemaDescriptorRejected
from .report_crypto_descriptors import (
    REPORT_AAD_PURPOSE,
    REPORT_AEAD_ALGORITHM_ID,
    REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
    REPORT_ATTEMPT_ID_BYTES,
    REPORT_CONTENT_PROFILE_ID,
    REPORT_CRYPTO_PROTOCOL_VERSION,
    REPORT_ID_BYTES,
    REPORT_KEY_HANDLE_BYTES,
    REPORT_NONCE_BYTES,
    REPORT_OBJECT_ID_BYTES,
    REPORT_OBJECT_KINDS_V1,
    REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
)


REPORT_OBJECT_SLOT_VALUES_V1 = (0, 1, 2, 3, 4)


class ReportSchemaKind(StrEnum):
    AAD = "AAD"
    CIPHERTEXT_ENVELOPE = "CIPHERTEXT_ENVELOPE"


class ReportSchemaFieldType(StrEnum):
    UINT = "UINT"
    TEXT = "TEXT"
    BYTES = "BYTES"


@dataclass(frozen=True, slots=True)
class ReportSchemaFieldV1:
    name: str
    field_type: ReportSchemaFieldType
    size_bytes: int | None
    exact_value: int | str | None
    allowed_values: tuple[int | str, ...]
    allowed_size_bytes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ReportSchemaProfileV1:
    scheme_version: int
    aad_schema_kind: ReportSchemaKind
    aad_fields: tuple[ReportSchemaFieldV1, ...]
    envelope_schema_kind: ReportSchemaKind
    envelope_fields: tuple[ReportSchemaFieldV1, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidReportSchemaProfileV1:
    profile: ReportSchemaProfileV1

    @property
    def encodes_cbor(self) -> bool:
        return False

    @property
    def parses_cbor(self) -> bool:
        return False

    @property
    def holds_context_values(self) -> bool:
        return False

    @property
    def holds_ciphertext(self) -> bool:
        return False

    @property
    def streams_attachments(self) -> bool:
        return False

    @property
    def authorizes_report_use(self) -> bool:
        return False


REPORT_OBJECT_KIND_VALUES_V1 = tuple(kind.value for kind in REPORT_OBJECT_KINDS_V1)

REPORT_FRAME_LENGTH_VALUES_V1 = (
    REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
    REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
)

REPORT_CIPHERTEXT_AND_TAG_SIZE_VALUES_V1 = (
    REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,
    REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES,
)

REPORT_AAD_SCHEMA_FIELDS_V1 = (
    ReportSchemaFieldV1(
        "version",
        ReportSchemaFieldType.UINT,
        None,
        REPORT_CRYPTO_PROTOCOL_VERSION,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "purpose",
        ReportSchemaFieldType.TEXT,
        None,
        REPORT_AAD_PURPOSE,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "algorithm",
        ReportSchemaFieldType.UINT,
        None,
        REPORT_AEAD_ALGORITHM_ID,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "content_profile",
        ReportSchemaFieldType.UINT,
        None,
        REPORT_CONTENT_PROFILE_ID,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "report_id",
        ReportSchemaFieldType.BYTES,
        REPORT_ID_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "attempt_id",
        ReportSchemaFieldType.BYTES,
        REPORT_ATTEMPT_ID_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "object_id",
        ReportSchemaFieldType.BYTES,
        REPORT_OBJECT_ID_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "object_kind",
        ReportSchemaFieldType.TEXT,
        None,
        None,
        REPORT_OBJECT_KIND_VALUES_V1,
        (),
    ),
    ReportSchemaFieldV1(
        "object_slot",
        ReportSchemaFieldType.UINT,
        None,
        None,
        REPORT_OBJECT_SLOT_VALUES_V1,
        (),
    ),
    ReportSchemaFieldV1(
        "report_key_handle",
        ReportSchemaFieldType.BYTES,
        REPORT_KEY_HANDLE_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "plaintext_frame_length",
        ReportSchemaFieldType.UINT,
        None,
        None,
        REPORT_FRAME_LENGTH_VALUES_V1,
        (),
    ),
)

REPORT_ENVELOPE_SCHEMA_FIELDS_V1 = (
    ReportSchemaFieldV1(
        "version",
        ReportSchemaFieldType.UINT,
        None,
        REPORT_CRYPTO_PROTOCOL_VERSION,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "algorithm",
        ReportSchemaFieldType.UINT,
        None,
        REPORT_AEAD_ALGORITHM_ID,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "content_profile",
        ReportSchemaFieldType.UINT,
        None,
        REPORT_CONTENT_PROFILE_ID,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "report_id",
        ReportSchemaFieldType.BYTES,
        REPORT_ID_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "attempt_id",
        ReportSchemaFieldType.BYTES,
        REPORT_ATTEMPT_ID_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "object_id",
        ReportSchemaFieldType.BYTES,
        REPORT_OBJECT_ID_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "object_kind",
        ReportSchemaFieldType.TEXT,
        None,
        None,
        REPORT_OBJECT_KIND_VALUES_V1,
        (),
    ),
    ReportSchemaFieldV1(
        "object_slot",
        ReportSchemaFieldType.UINT,
        None,
        None,
        REPORT_OBJECT_SLOT_VALUES_V1,
        (),
    ),
    ReportSchemaFieldV1(
        "report_key_handle",
        ReportSchemaFieldType.BYTES,
        REPORT_KEY_HANDLE_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "nonce",
        ReportSchemaFieldType.BYTES,
        REPORT_NONCE_BYTES,
        None,
        (),
        (),
    ),
    ReportSchemaFieldV1(
        "ciphertext_and_tag",
        ReportSchemaFieldType.BYTES,
        None,
        None,
        (),
        REPORT_CIPHERTEXT_AND_TAG_SIZE_VALUES_V1,
    ),
)


def _reject() -> Never:
    raise ReportSchemaDescriptorRejected()


def _require_schema_kind(
    value: object,
    *,
    expected: ReportSchemaKind,
) -> ReportSchemaKind:
    if isinstance(value, ReportSchemaKind):
        if value == expected:
            return value
        _reject()
    if type(value) is str and value == expected.value:
        return expected
    _reject()


def _require_field_type(value: object) -> ReportSchemaFieldType:
    if isinstance(value, ReportSchemaFieldType):
        return value
    if type(value) is str:
        for field_type in ReportSchemaFieldType:
            if value == field_type.value:
                return field_type
    _reject()


def _require_allowed_values(value: object) -> tuple[int | str, ...]:
    if type(value) is not tuple:
        _reject()
    for item in value:
        if type(item) not in (int, str):
            _reject()
    return value


def _require_allowed_size_bytes(value: object) -> tuple[int, ...]:
    if type(value) is not tuple:
        _reject()
    for item in value:
        if type(item) is not int or item <= 0:
            _reject()
    return value


def _normalize_field(field: ReportSchemaFieldV1) -> ReportSchemaFieldV1:
    if type(field) is not ReportSchemaFieldV1:
        _reject()
    if type(field.name) is not str:
        _reject()
    if field.size_bytes is not None:
        if type(field.size_bytes) is not int or field.size_bytes <= 0:
            _reject()
    if field.exact_value is not None:
        if type(field.exact_value) not in (int, str):
            _reject()
    return ReportSchemaFieldV1(
        name=field.name,
        field_type=_require_field_type(field.field_type),
        size_bytes=field.size_bytes,
        exact_value=field.exact_value,
        allowed_values=_require_allowed_values(field.allowed_values),
        allowed_size_bytes=_require_allowed_size_bytes(
            field.allowed_size_bytes
        ),
    )


def _require_fields_exact(
    value: object,
    *,
    expected: tuple[ReportSchemaFieldV1, ...],
) -> tuple[ReportSchemaFieldV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_normalize_field(field) for field in value)
    if normalized != expected:
        _reject()
    return normalized


def validate_report_schema_profile_v1(
    profile: ReportSchemaProfileV1,
) -> StructurallyValidReportSchemaProfileV1:
    if type(profile) is not ReportSchemaProfileV1:
        _reject()
    if type(profile.scheme_version) is not int:
        _reject()
    if profile.scheme_version != REPORT_CRYPTO_PROTOCOL_VERSION:
        _reject()
    normalized = ReportSchemaProfileV1(
        scheme_version=profile.scheme_version,
        aad_schema_kind=_require_schema_kind(
            profile.aad_schema_kind,
            expected=ReportSchemaKind.AAD,
        ),
        aad_fields=_require_fields_exact(
            profile.aad_fields,
            expected=REPORT_AAD_SCHEMA_FIELDS_V1,
        ),
        envelope_schema_kind=_require_schema_kind(
            profile.envelope_schema_kind,
            expected=ReportSchemaKind.CIPHERTEXT_ENVELOPE,
        ),
        envelope_fields=_require_fields_exact(
            profile.envelope_fields,
            expected=REPORT_ENVELOPE_SCHEMA_FIELDS_V1,
        ),
    )
    return StructurallyValidReportSchemaProfileV1(profile=normalized)


def expected_report_schema_profile_v1() -> ReportSchemaProfileV1:
    """Return only the approved schema metadata; never protected values."""

    return ReportSchemaProfileV1(
        scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
        aad_schema_kind=ReportSchemaKind.AAD,
        aad_fields=REPORT_AAD_SCHEMA_FIELDS_V1,
        envelope_schema_kind=ReportSchemaKind.CIPHERTEXT_ENVELOPE,
        envelope_fields=REPORT_ENVELOPE_SCHEMA_FIELDS_V1,
    )
