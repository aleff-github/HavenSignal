"""Inert Response Note text descriptors from the approved v1 profile.

This module performs only transient profile validation and returns content-free
shape evidence. It does not retain text, create drafts, produce canonical
bytes, compute digests, create frames, persist content, or authorize use.
"""

import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import ResponseTextDescriptorRejected


RESPONSE_TEXT_PROFILE_VERSION = 1
RESPONSE_TEXT_MAX_SCALAR_VALUES = 5_000
RESPONSE_TEXT_MAX_UTF8_BYTES = 20_000
RESPONSE_TEXT_UNICODE_NORMALIZATION = "NFC"
RESPONSE_TEXT_LINE_ENDING_PROFILE = "LF"
RESPONSE_TEXT_ENCODING = "UTF-8"
RESPONSE_TEXT_CONTENT_KIND = "PLAIN_TEXT"
RESPONSE_TEXT_FORBIDDEN_CODEPOINTS = frozenset({0})
RESPONSE_TEXT_FORBIDDEN_CHARACTERS = frozenset({"<", ">"})
RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS = (
    "http://",
    "https://",
    "mailto:",
    "tel:",
    "ftp://",
    "www.",
)


class ResponseTextNormalization(StrEnum):
    NFC = "NFC"


class ResponseTextLineEnding(StrEnum):
    LF = "LF"


class ResponseTextEncoding(StrEnum):
    UTF8 = "UTF-8"


class ResponseTextContentKind(StrEnum):
    PLAIN_TEXT = "PLAIN_TEXT"


@dataclass(frozen=True, slots=True)
class ResponseTextCanonicalizationProfileV1:
    scheme_version: int
    normalization: ResponseTextNormalization
    line_ending: ResponseTextLineEnding
    encoding: ResponseTextEncoding


@dataclass(frozen=True, slots=True)
class ResponseTextLimitProfileV1:
    max_scalar_values: int
    max_utf8_bytes: int


@dataclass(frozen=True, slots=True)
class ResponseTextContentRestrictionProfileV1:
    content_kind: ResponseTextContentKind
    forbidden_codepoints: frozenset[int]
    forbidden_characters: frozenset[str]
    forbidden_link_markers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidResponseTextProfileV1:
    canonicalization_profile: ResponseTextCanonicalizationProfileV1
    limit_profile: ResponseTextLimitProfileV1
    content_restriction_profile: ResponseTextContentRestrictionProfileV1

    @property
    def retains_response_text(self) -> bool:
        return False

    @property
    def creates_server_side_draft(self) -> bool:
        return False

    @property
    def produces_canonical_bytes(self) -> bool:
        return False

    @property
    def computes_artifact_digest(self) -> bool:
        return False

    @property
    def authorizes_finalization(self) -> bool:
        return False


def _reject() -> Never:
    raise ResponseTextDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_normalization(value: object) -> ResponseTextNormalization:
    if isinstance(value, ResponseTextNormalization):
        if value == ResponseTextNormalization.NFC:
            return value
        _reject()
    if type(value) is str and value == ResponseTextNormalization.NFC.value:
        return ResponseTextNormalization.NFC
    _reject()


def _require_line_ending(value: object) -> ResponseTextLineEnding:
    if isinstance(value, ResponseTextLineEnding):
        if value == ResponseTextLineEnding.LF:
            return value
        _reject()
    if type(value) is str and value == ResponseTextLineEnding.LF.value:
        return ResponseTextLineEnding.LF
    _reject()


def _require_encoding(value: object) -> ResponseTextEncoding:
    if isinstance(value, ResponseTextEncoding):
        if value == ResponseTextEncoding.UTF8:
            return value
        _reject()
    if type(value) is str and value == ResponseTextEncoding.UTF8.value:
        return ResponseTextEncoding.UTF8
    _reject()


def _require_content_kind(value: object) -> ResponseTextContentKind:
    if isinstance(value, ResponseTextContentKind):
        if value == ResponseTextContentKind.PLAIN_TEXT:
            return value
        _reject()
    if type(value) is str and value == ResponseTextContentKind.PLAIN_TEXT.value:
        return ResponseTextContentKind.PLAIN_TEXT
    _reject()


def _require_codepoint_set(value: object) -> frozenset[int]:
    if type(value) is not frozenset or value != RESPONSE_TEXT_FORBIDDEN_CODEPOINTS:
        _reject()
    return value


def _require_character_set(value: object) -> frozenset[str]:
    if type(value) is not frozenset or value != RESPONSE_TEXT_FORBIDDEN_CHARACTERS:
        _reject()
    return value


def _require_link_markers(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or value != RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS:
        _reject()
    for marker in value:
        if type(marker) is not str or marker != marker.lower():
            _reject()
    return value


def _normalized_candidate(value: object) -> str:
    if type(value) is not str:
        _reject()
    for character in value:
        codepoint = ord(character)
        if codepoint in RESPONSE_TEXT_FORBIDDEN_CODEPOINTS:
            _reject()
        if 0xD800 <= codepoint <= 0xDFFF:
            _reject()
        if character in RESPONSE_TEXT_FORBIDDEN_CHARACTERS:
            _reject()
    line_normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = unicodedata.normalize(
        RESPONSE_TEXT_UNICODE_NORMALIZATION,
        line_normalized,
    )
    lowered = normalized.lower()
    for marker in RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS:
        if marker in lowered:
            _reject()
    if len(normalized) > RESPONSE_TEXT_MAX_SCALAR_VALUES:
        _reject()
    try:
        encoded = normalized.encode(RESPONSE_TEXT_ENCODING, errors="strict")
    except UnicodeError:
        _reject()
    if len(encoded) > RESPONSE_TEXT_MAX_UTF8_BYTES:
        _reject()
    return normalized


def validate_response_text_canonicalization_profile_v1(
    profile: ResponseTextCanonicalizationProfileV1,
) -> ResponseTextCanonicalizationProfileV1:
    if type(profile) is not ResponseTextCanonicalizationProfileV1:
        _reject()
    return ResponseTextCanonicalizationProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RESPONSE_TEXT_PROFILE_VERSION,
        ),
        normalization=_require_normalization(profile.normalization),
        line_ending=_require_line_ending(profile.line_ending),
        encoding=_require_encoding(profile.encoding),
    )


def validate_response_text_limit_profile_v1(
    profile: ResponseTextLimitProfileV1,
) -> ResponseTextLimitProfileV1:
    if type(profile) is not ResponseTextLimitProfileV1:
        _reject()
    return ResponseTextLimitProfileV1(
        max_scalar_values=_require_uint_exact(
            profile.max_scalar_values,
            expected=RESPONSE_TEXT_MAX_SCALAR_VALUES,
        ),
        max_utf8_bytes=_require_uint_exact(
            profile.max_utf8_bytes,
            expected=RESPONSE_TEXT_MAX_UTF8_BYTES,
        ),
    )


def validate_response_text_content_restriction_profile_v1(
    profile: ResponseTextContentRestrictionProfileV1,
) -> ResponseTextContentRestrictionProfileV1:
    if type(profile) is not ResponseTextContentRestrictionProfileV1:
        _reject()
    return ResponseTextContentRestrictionProfileV1(
        content_kind=_require_content_kind(profile.content_kind),
        forbidden_codepoints=_require_codepoint_set(
            profile.forbidden_codepoints
        ),
        forbidden_characters=_require_character_set(
            profile.forbidden_characters
        ),
        forbidden_link_markers=_require_link_markers(
            profile.forbidden_link_markers
        ),
    )


def validate_response_text_candidate_v1(
    value: object,
) -> StructurallyValidResponseTextProfileV1:
    """Validate a candidate transiently; return no Response Note material."""

    _normalized_candidate(value)
    return validate_response_text_profile_v1(
        canonicalization_profile=ResponseTextCanonicalizationProfileV1(
            scheme_version=RESPONSE_TEXT_PROFILE_VERSION,
            normalization=ResponseTextNormalization.NFC,
            line_ending=ResponseTextLineEnding.LF,
            encoding=ResponseTextEncoding.UTF8,
        ),
        limit_profile=ResponseTextLimitProfileV1(
            max_scalar_values=RESPONSE_TEXT_MAX_SCALAR_VALUES,
            max_utf8_bytes=RESPONSE_TEXT_MAX_UTF8_BYTES,
        ),
        content_restriction_profile=ResponseTextContentRestrictionProfileV1(
            content_kind=ResponseTextContentKind.PLAIN_TEXT,
            forbidden_codepoints=RESPONSE_TEXT_FORBIDDEN_CODEPOINTS,
            forbidden_characters=RESPONSE_TEXT_FORBIDDEN_CHARACTERS,
            forbidden_link_markers=RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS,
        ),
    )


def validate_response_text_profile_v1(
    *,
    canonicalization_profile: ResponseTextCanonicalizationProfileV1,
    limit_profile: ResponseTextLimitProfileV1,
    content_restriction_profile: ResponseTextContentRestrictionProfileV1,
) -> StructurallyValidResponseTextProfileV1:
    """Validate only exact v1 text profile shapes; never authorize use."""

    return StructurallyValidResponseTextProfileV1(
        canonicalization_profile=(
            validate_response_text_canonicalization_profile_v1(
                canonicalization_profile
            )
        ),
        limit_profile=validate_response_text_limit_profile_v1(limit_profile),
        content_restriction_profile=(
            validate_response_text_content_restriction_profile_v1(
                content_restriction_profile
            )
        ),
    )
