"""Inert Response Note AAD/envelope schema descriptors for v1.

This module validates only ordered schema metadata. It does not encode CBOR,
parse envelopes, hold identifiers, hold ciphertext, call services, or authorize
response use.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import ResponseSchemaDescriptorRejected
from .response_crypto_descriptors import (
    RESPONSE_AAD_PURPOSE,
    RESPONSE_AEAD_ALGORITHM_ID,
    RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
    RESPONSE_CONTENT_PROFILE_ID,
    RESPONSE_CRYPTO_PROTOCOL_VERSION,
    RESPONSE_FINALIZATION_ID_BYTES,
    RESPONSE_ID_BYTES,
    RESPONSE_KEY_HANDLE_BYTES,
    RESPONSE_NONCE_BYTES,
    RESPONSE_PLAINTEXT_FRAME_BYTES,
    RESPONSE_REPORT_ID_BYTES,
)


class ResponseSchemaKind(StrEnum):
    AAD = "AAD"
    CIPHERTEXT_ENVELOPE = "CIPHERTEXT_ENVELOPE"


class ResponseSchemaFieldType(StrEnum):
    UINT = "UINT"
    TEXT = "TEXT"
    BYTES = "BYTES"


@dataclass(frozen=True, slots=True)
class ResponseSchemaFieldV1:
    name: str
    field_type: ResponseSchemaFieldType
    size_bytes: int | None
    exact_value: int | str | None


@dataclass(frozen=True, slots=True)
class ResponseSchemaProfileV1:
    scheme_version: int
    aad_schema_kind: ResponseSchemaKind
    aad_fields: tuple[ResponseSchemaFieldV1, ...]
    envelope_schema_kind: ResponseSchemaKind
    envelope_fields: tuple[ResponseSchemaFieldV1, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidResponseSchemaProfileV1:
    profile: ResponseSchemaProfileV1

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
    def authorizes_response_use(self) -> bool:
        return False


RESPONSE_AAD_SCHEMA_FIELDS_V1 = (
    ResponseSchemaFieldV1("version", ResponseSchemaFieldType.UINT, None, 1),
    ResponseSchemaFieldV1(
        "purpose",
        ResponseSchemaFieldType.TEXT,
        None,
        RESPONSE_AAD_PURPOSE,
    ),
    ResponseSchemaFieldV1(
        "algorithm",
        ResponseSchemaFieldType.UINT,
        None,
        RESPONSE_AEAD_ALGORITHM_ID,
    ),
    ResponseSchemaFieldV1(
        "content_profile",
        ResponseSchemaFieldType.UINT,
        None,
        RESPONSE_CONTENT_PROFILE_ID,
    ),
    ResponseSchemaFieldV1(
        "report_id",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_REPORT_ID_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "response_id",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_ID_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "finalization_id",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_FINALIZATION_ID_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "response_key_handle",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_KEY_HANDLE_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "plaintext_frame_length",
        ResponseSchemaFieldType.UINT,
        None,
        RESPONSE_PLAINTEXT_FRAME_BYTES,
    ),
)

RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1 = (
    ResponseSchemaFieldV1("version", ResponseSchemaFieldType.UINT, None, 1),
    ResponseSchemaFieldV1(
        "algorithm",
        ResponseSchemaFieldType.UINT,
        None,
        RESPONSE_AEAD_ALGORITHM_ID,
    ),
    ResponseSchemaFieldV1(
        "content_profile",
        ResponseSchemaFieldType.UINT,
        None,
        RESPONSE_CONTENT_PROFILE_ID,
    ),
    ResponseSchemaFieldV1(
        "report_id",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_REPORT_ID_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "response_id",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_ID_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "finalization_id",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_FINALIZATION_ID_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "response_key_handle",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_KEY_HANDLE_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "nonce",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_NONCE_BYTES,
        None,
    ),
    ResponseSchemaFieldV1(
        "ciphertext_and_tag",
        ResponseSchemaFieldType.BYTES,
        RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
        None,
    ),
)


def _reject() -> Never:
    raise ResponseSchemaDescriptorRejected()


def _require_schema_kind(
    value: object,
    *,
    expected: ResponseSchemaKind,
) -> ResponseSchemaKind:
    if isinstance(value, ResponseSchemaKind):
        if value == expected:
            return value
        _reject()
    if type(value) is str and value == expected.value:
        return expected
    _reject()


def _require_field_type(value: object) -> ResponseSchemaFieldType:
    if isinstance(value, ResponseSchemaFieldType):
        return value
    if type(value) is str:
        for field_type in ResponseSchemaFieldType:
            if value == field_type.value:
                return field_type
    _reject()


def _normalize_field(field: ResponseSchemaFieldV1) -> ResponseSchemaFieldV1:
    if type(field) is not ResponseSchemaFieldV1:
        _reject()
    if type(field.name) is not str:
        _reject()
    if field.size_bytes is not None:
        if type(field.size_bytes) is not int or field.size_bytes <= 0:
            _reject()
    if field.exact_value is not None:
        if type(field.exact_value) not in (int, str):
            _reject()
    return ResponseSchemaFieldV1(
        name=field.name,
        field_type=_require_field_type(field.field_type),
        size_bytes=field.size_bytes,
        exact_value=field.exact_value,
    )


def _require_fields_exact(
    value: object,
    *,
    expected: tuple[ResponseSchemaFieldV1, ...],
) -> tuple[ResponseSchemaFieldV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_normalize_field(field) for field in value)
    if normalized != expected:
        _reject()
    return normalized


def validate_response_schema_profile_v1(
    profile: ResponseSchemaProfileV1,
) -> StructurallyValidResponseSchemaProfileV1:
    if type(profile) is not ResponseSchemaProfileV1:
        _reject()
    if type(profile.scheme_version) is not int:
        _reject()
    if profile.scheme_version != RESPONSE_CRYPTO_PROTOCOL_VERSION:
        _reject()
    normalized = ResponseSchemaProfileV1(
        scheme_version=profile.scheme_version,
        aad_schema_kind=_require_schema_kind(
            profile.aad_schema_kind,
            expected=ResponseSchemaKind.AAD,
        ),
        aad_fields=_require_fields_exact(
            profile.aad_fields,
            expected=RESPONSE_AAD_SCHEMA_FIELDS_V1,
        ),
        envelope_schema_kind=_require_schema_kind(
            profile.envelope_schema_kind,
            expected=ResponseSchemaKind.CIPHERTEXT_ENVELOPE,
        ),
        envelope_fields=_require_fields_exact(
            profile.envelope_fields,
            expected=RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1,
        ),
    )
    return StructurallyValidResponseSchemaProfileV1(profile=normalized)


def expected_response_schema_profile_v1() -> ResponseSchemaProfileV1:
    """Return only the approved schema metadata; never protected values."""

    return ResponseSchemaProfileV1(
        scheme_version=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        aad_schema_kind=ResponseSchemaKind.AAD,
        aad_fields=RESPONSE_AAD_SCHEMA_FIELDS_V1,
        envelope_schema_kind=ResponseSchemaKind.CIPHERTEXT_ENVELOPE,
        envelope_fields=RESPONSE_ENVELOPE_SCHEMA_FIELDS_V1,
    )
