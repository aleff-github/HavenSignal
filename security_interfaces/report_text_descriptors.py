"""Inert original-report text descriptors from the approved v1 profile.

This module performs only transient profile validation and returns content-free
shape evidence. It does not retain browser/wire text, return canonical bytes,
create frames, encrypt content, persist content, log content, or authorize
submission.
"""

import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import ReportTextDescriptorRejected


REPORT_TEXT_PROFILE_VERSION = 1
REPORT_TEXT_MAX_SCALAR_VALUES = 5_000
REPORT_TEXT_MAX_UTF8_BYTES = 20_000
REPORT_TEXT_UNICODE_NORMALIZATION = "NFC"
REPORT_TEXT_LINE_ENDING_PROFILE = "LF"
REPORT_TEXT_ENCODING = "UTF-8"
REPORT_TEXT_ACCEPTED_ORIGINAL_KIND = "CANONICAL_UTF8_REPORT_TEXT"
REPORT_TEXT_FORBIDDEN_CODEPOINTS = frozenset({0})


class ReportTextNormalization(StrEnum):
    NFC = "NFC"


class ReportTextLineEnding(StrEnum):
    LF = "LF"


class ReportTextEncoding(StrEnum):
    UTF8 = "UTF-8"


class ReportTextAcceptedOriginalKind(StrEnum):
    CANONICAL_UTF8_REPORT_TEXT = "CANONICAL_UTF8_REPORT_TEXT"


@dataclass(frozen=True, slots=True)
class ReportTextCanonicalizationProfileV1:
    scheme_version: int
    normalization: ReportTextNormalization
    line_ending: ReportTextLineEnding
    encoding: ReportTextEncoding
    accepted_original_kind: ReportTextAcceptedOriginalKind


@dataclass(frozen=True, slots=True)
class ReportTextLimitProfileV1:
    max_scalar_values: int
    max_utf8_bytes: int


@dataclass(frozen=True, slots=True)
class ReportTextCharacterProfileV1:
    forbidden_codepoints: frozenset[int]
    rejects_unpaired_surrogates: bool


@dataclass(frozen=True, slots=True)
class StructurallyValidReportTextProfileV1:
    canonicalization_profile: ReportTextCanonicalizationProfileV1
    limit_profile: ReportTextLimitProfileV1
    character_profile: ReportTextCharacterProfileV1

    @property
    def retains_wire_report_text(self) -> bool:
        return False

    @property
    def returns_canonical_bytes(self) -> bool:
        return False

    @property
    def creates_plaintext_frame(self) -> bool:
        return False

    @property
    def encrypts_report_text(self) -> bool:
        return False

    @property
    def persists_report_text(self) -> bool:
        return False

    @property
    def logs_report_text(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise ReportTextDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_normalization(value: object) -> ReportTextNormalization:
    if isinstance(value, ReportTextNormalization):
        if value == ReportTextNormalization.NFC:
            return value
        _reject()
    if type(value) is str and value == ReportTextNormalization.NFC.value:
        return ReportTextNormalization.NFC
    _reject()


def _require_line_ending(value: object) -> ReportTextLineEnding:
    if isinstance(value, ReportTextLineEnding):
        if value == ReportTextLineEnding.LF:
            return value
        _reject()
    if type(value) is str and value == ReportTextLineEnding.LF.value:
        return ReportTextLineEnding.LF
    _reject()


def _require_encoding(value: object) -> ReportTextEncoding:
    if isinstance(value, ReportTextEncoding):
        if value == ReportTextEncoding.UTF8:
            return value
        _reject()
    if type(value) is str and value == ReportTextEncoding.UTF8.value:
        return ReportTextEncoding.UTF8
    _reject()


def _require_accepted_original_kind(
    value: object,
) -> ReportTextAcceptedOriginalKind:
    if isinstance(value, ReportTextAcceptedOriginalKind):
        if (
            value
            == ReportTextAcceptedOriginalKind.CANONICAL_UTF8_REPORT_TEXT
        ):
            return value
        _reject()
    if (
        type(value) is str
        and value
        == ReportTextAcceptedOriginalKind.CANONICAL_UTF8_REPORT_TEXT.value
    ):
        return ReportTextAcceptedOriginalKind.CANONICAL_UTF8_REPORT_TEXT
    _reject()


def _require_codepoint_set(value: object) -> frozenset[int]:
    if type(value) is not frozenset or value != REPORT_TEXT_FORBIDDEN_CODEPOINTS:
        _reject()
    return value


def _normalized_candidate(value: object) -> str:
    if type(value) is not str:
        _reject()
    for character in value:
        codepoint = ord(character)
        if codepoint in REPORT_TEXT_FORBIDDEN_CODEPOINTS:
            _reject()
        if 0xD800 <= codepoint <= 0xDFFF:
            _reject()
    line_normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = unicodedata.normalize(
        REPORT_TEXT_UNICODE_NORMALIZATION,
        line_normalized,
    )
    if len(normalized) > REPORT_TEXT_MAX_SCALAR_VALUES:
        _reject()
    try:
        encoded = normalized.encode(REPORT_TEXT_ENCODING, errors="strict")
    except UnicodeError:
        _reject()
    if len(encoded) > REPORT_TEXT_MAX_UTF8_BYTES:
        _reject()
    return normalized


def validate_report_text_canonicalization_profile_v1(
    profile: ReportTextCanonicalizationProfileV1,
) -> ReportTextCanonicalizationProfileV1:
    if type(profile) is not ReportTextCanonicalizationProfileV1:
        _reject()
    return ReportTextCanonicalizationProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=REPORT_TEXT_PROFILE_VERSION,
        ),
        normalization=_require_normalization(profile.normalization),
        line_ending=_require_line_ending(profile.line_ending),
        encoding=_require_encoding(profile.encoding),
        accepted_original_kind=_require_accepted_original_kind(
            profile.accepted_original_kind
        ),
    )


def validate_report_text_limit_profile_v1(
    profile: ReportTextLimitProfileV1,
) -> ReportTextLimitProfileV1:
    if type(profile) is not ReportTextLimitProfileV1:
        _reject()
    return ReportTextLimitProfileV1(
        max_scalar_values=_require_uint_exact(
            profile.max_scalar_values,
            expected=REPORT_TEXT_MAX_SCALAR_VALUES,
        ),
        max_utf8_bytes=_require_uint_exact(
            profile.max_utf8_bytes,
            expected=REPORT_TEXT_MAX_UTF8_BYTES,
        ),
    )


def validate_report_text_character_profile_v1(
    profile: ReportTextCharacterProfileV1,
) -> ReportTextCharacterProfileV1:
    if type(profile) is not ReportTextCharacterProfileV1:
        _reject()
    return ReportTextCharacterProfileV1(
        forbidden_codepoints=_require_codepoint_set(
            profile.forbidden_codepoints
        ),
        rejects_unpaired_surrogates=_require_bool_exact(
            profile.rejects_unpaired_surrogates,
            expected=True,
        ),
    )


def validate_report_text_candidate_v1(
    value: object,
) -> StructurallyValidReportTextProfileV1:
    """Validate a candidate transiently; return no report material."""

    _normalized_candidate(value)
    return validate_report_text_profile_v1(
        canonicalization_profile=ReportTextCanonicalizationProfileV1(
            scheme_version=REPORT_TEXT_PROFILE_VERSION,
            normalization=ReportTextNormalization.NFC,
            line_ending=ReportTextLineEnding.LF,
            encoding=ReportTextEncoding.UTF8,
            accepted_original_kind=(
                ReportTextAcceptedOriginalKind.CANONICAL_UTF8_REPORT_TEXT
            ),
        ),
        limit_profile=ReportTextLimitProfileV1(
            max_scalar_values=REPORT_TEXT_MAX_SCALAR_VALUES,
            max_utf8_bytes=REPORT_TEXT_MAX_UTF8_BYTES,
        ),
        character_profile=ReportTextCharacterProfileV1(
            forbidden_codepoints=REPORT_TEXT_FORBIDDEN_CODEPOINTS,
            rejects_unpaired_surrogates=True,
        ),
    )


def validate_report_text_profile_v1(
    *,
    canonicalization_profile: ReportTextCanonicalizationProfileV1,
    limit_profile: ReportTextLimitProfileV1,
    character_profile: ReportTextCharacterProfileV1,
) -> StructurallyValidReportTextProfileV1:
    """Validate only exact v1 text profile shapes; never authorize use."""

    return StructurallyValidReportTextProfileV1(
        canonicalization_profile=(
            validate_report_text_canonicalization_profile_v1(
                canonicalization_profile
            )
        ),
        limit_profile=validate_report_text_limit_profile_v1(limit_profile),
        character_profile=validate_report_text_character_profile_v1(
            character_profile
        ),
    )
