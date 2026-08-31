"""Inert no-JavaScript CAPTCHA descriptors from the approved v1 profile.

This module validates only static challenge metadata and strict text shapes. It
does not generate challenges, render media, persist records, compare answers,
read requests, call a Challenge Service, or authorize any protected operation.
"""

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import CaptchaDescriptorRejected


CAPTCHA_PROTOCOL_VERSION = 1
CAPTCHA_IDENTIFIER_RAW_BYTES = 16
CAPTCHA_IDENTIFIER_ENCODED_LENGTH = 22
CAPTCHA_FORM_SCOPE_RAW_BYTES = 16
CAPTCHA_ANSWER_LENGTH = 6
CAPTCHA_EXPIRY_SECONDS = 300
CAPTCHA_CLEANUP_AFTER_SECONDS = 900
CAPTCHA_PNG_WIDTH_PIXELS = 240
CAPTCHA_PNG_HEIGHT_PIXELS = 80
CAPTCHA_PNG_MAX_BYTES = 65_536

CAPTCHA_IDENTIFIER_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-"
)
CAPTCHA_ANSWER_ALPHABET = frozenset("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")


class CaptchaPurpose(StrEnum):
    SUBMIT_REPORT = "SUBMIT_REPORT"
    RECOVER_RESPONSE = "RECOVER_RESPONSE"


class CaptchaAction(StrEnum):
    ISSUE = "ISSUE"
    VERIFY = "VERIFY"
    FETCH_REPRESENTATION = "FETCH_REPRESENTATION"


class CaptchaChallengeState(StrEnum):
    READY = "READY"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class CaptchaProductionGate(StrEnum):
    PINNED_PILLOW_AND_FONT_REVIEW = "PINNED_PILLOW_AND_FONT_REVIEW"
    SELF_HOSTED_AUDIO_ACCESSIBILITY_REVIEW = (
        "SELF_HOSTED_AUDIO_ACCESSIBILITY_REVIEW"
    )
    POSTGRESQL_CONCURRENCY_REVIEW = "POSTGRESQL_CONCURRENCY_REVIEW"
    PRODUCTION_BOUNDARY_REVIEW = "PRODUCTION_BOUNDARY_REVIEW"


CAPTCHA_PURPOSES_V1 = (
    CaptchaPurpose.SUBMIT_REPORT,
    CaptchaPurpose.RECOVER_RESPONSE,
)
CAPTCHA_CHALLENGE_STATES_V1 = (
    CaptchaChallengeState.READY,
    CaptchaChallengeState.CONSUMED,
    CaptchaChallengeState.EXPIRED,
)
CAPTCHA_PRODUCTION_GATES_V1 = (
    CaptchaProductionGate.PINNED_PILLOW_AND_FONT_REVIEW,
    CaptchaProductionGate.SELF_HOSTED_AUDIO_ACCESSIBILITY_REVIEW,
    CaptchaProductionGate.POSTGRESQL_CONCURRENCY_REVIEW,
    CaptchaProductionGate.PRODUCTION_BOUNDARY_REVIEW,
)


@dataclass(frozen=True, slots=True)
class CaptchaIdentifierShapeV1:
    raw_size_bytes: int
    encoded_length: int
    alphabet: frozenset[str]


@dataclass(frozen=True, slots=True)
class CaptchaAnswerShapeV1:
    answer_length: int
    alphabet: frozenset[str]


@dataclass(frozen=True, slots=True)
class CaptchaFormScopeShapeV1:
    raw_size_bytes: int


@dataclass(frozen=True, slots=True)
class CaptchaTimingProfileV1:
    expiry_seconds: int
    cleanup_after_seconds: int


@dataclass(frozen=True, slots=True)
class CaptchaStateProfileV1:
    allowed_states: tuple[CaptchaChallengeState, ...]


@dataclass(frozen=True, slots=True)
class CaptchaPurposeProfileV1:
    allowed_purposes: tuple[CaptchaPurpose, ...]


@dataclass(frozen=True, slots=True)
class CaptchaRepresentationProfileV1:
    png_width_pixels: int
    png_height_pixels: int
    png_max_bytes: int
    audio_required_before_production: bool


@dataclass(frozen=True, slots=True)
class CaptchaBucketLimitV1:
    purpose: CaptchaPurpose
    action: CaptchaAction
    capacity: int
    refill_tokens: int
    refill_period_seconds: int


@dataclass(frozen=True, slots=True)
class CaptchaAbuseControlProfileV1:
    bucket_limits: tuple[CaptchaBucketLimitV1, ...]
    uses_network_identity_keys: bool


@dataclass(frozen=True, slots=True)
class CaptchaProductionGateProfileV1:
    open_gates: tuple[CaptchaProductionGate, ...]
    production_enabled: bool


@dataclass(frozen=True, slots=True)
class CaptchaProtocolProfileV1:
    scheme_version: int
    identifier_shape: CaptchaIdentifierShapeV1
    answer_shape: CaptchaAnswerShapeV1
    form_scope_shape: CaptchaFormScopeShapeV1
    timing_profile: CaptchaTimingProfileV1
    state_profile: CaptchaStateProfileV1
    purpose_profile: CaptchaPurposeProfileV1
    representation_profile: CaptchaRepresentationProfileV1
    abuse_control_profile: CaptchaAbuseControlProfileV1
    production_gate_profile: CaptchaProductionGateProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidCaptchaProtocolProfileV1:
    profile: CaptchaProtocolProfileV1

    @property
    def generates_challenge(self) -> bool:
        return False

    @property
    def validates_answer(self) -> bool:
        return False

    @property
    def persists_challenge_record(self) -> bool:
        return False

    @property
    def renders_media(self) -> bool:
        return False

    @property
    def binds_to_network_identity(self) -> bool:
        return False

    @property
    def uses_third_party_captcha(self) -> bool:
        return False

    @property
    def authorizes_operation(self) -> bool:
        return False

    @property
    def enables_protected_endpoint(self) -> bool:
        return False


CAPTCHA_BUCKET_LIMITS_V1 = (
    CaptchaBucketLimitV1(
        CaptchaPurpose.SUBMIT_REPORT,
        CaptchaAction.ISSUE,
        20,
        1,
        2,
    ),
    CaptchaBucketLimitV1(
        CaptchaPurpose.SUBMIT_REPORT,
        CaptchaAction.VERIFY,
        20,
        1,
        3,
    ),
    CaptchaBucketLimitV1(
        CaptchaPurpose.SUBMIT_REPORT,
        CaptchaAction.FETCH_REPRESENTATION,
        120,
        2,
        1,
    ),
    CaptchaBucketLimitV1(
        CaptchaPurpose.RECOVER_RESPONSE,
        CaptchaAction.ISSUE,
        20,
        1,
        2,
    ),
    CaptchaBucketLimitV1(
        CaptchaPurpose.RECOVER_RESPONSE,
        CaptchaAction.VERIFY,
        20,
        1,
        3,
    ),
    CaptchaBucketLimitV1(
        CaptchaPurpose.RECOVER_RESPONSE,
        CaptchaAction.FETCH_REPRESENTATION,
        120,
        2,
        1,
    ),
)


def _reject() -> Never:
    raise CaptchaDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_frozenset_exact(
    value: object,
    *,
    expected: frozenset[str],
) -> frozenset[str]:
    if type(value) is not frozenset or value != expected:
        _reject()
    return value


def _require_purpose(value: object) -> CaptchaPurpose:
    if isinstance(value, CaptchaPurpose):
        return value
    if type(value) is str:
        for purpose in CaptchaPurpose:
            if value == purpose.value:
                return purpose
    _reject()


def _require_action(value: object) -> CaptchaAction:
    if isinstance(value, CaptchaAction):
        return value
    if type(value) is str:
        for action in CaptchaAction:
            if value == action.value:
                return action
    _reject()


def _require_state(value: object) -> CaptchaChallengeState:
    if isinstance(value, CaptchaChallengeState):
        return value
    if type(value) is str:
        for state in CaptchaChallengeState:
            if value == state.value:
                return state
    _reject()


def _require_gate(value: object) -> CaptchaProductionGate:
    if isinstance(value, CaptchaProductionGate):
        return value
    if type(value) is str:
        for gate in CaptchaProductionGate:
            if value == gate.value:
                return gate
    _reject()


def _require_purpose_sequence(value: object) -> tuple[CaptchaPurpose, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_purpose(purpose) for purpose in value)
    if normalized != CAPTCHA_PURPOSES_V1:
        _reject()
    return normalized


def _require_state_sequence(
    value: object,
) -> tuple[CaptchaChallengeState, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_state(state) for state in value)
    if normalized != CAPTCHA_CHALLENGE_STATES_V1:
        _reject()
    return normalized


def _require_gate_sequence(
    value: object,
) -> tuple[CaptchaProductionGate, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_gate(gate) for gate in value)
    if normalized != CAPTCHA_PRODUCTION_GATES_V1:
        _reject()
    return normalized


def _require_bucket_limit(limit: CaptchaBucketLimitV1) -> CaptchaBucketLimitV1:
    if type(limit) is not CaptchaBucketLimitV1:
        _reject()
    return CaptchaBucketLimitV1(
        purpose=_require_purpose(limit.purpose),
        action=_require_action(limit.action),
        capacity=limit.capacity,
        refill_tokens=limit.refill_tokens,
        refill_period_seconds=limit.refill_period_seconds,
    )


def _require_bucket_limits(
    value: object,
) -> tuple[CaptchaBucketLimitV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_bucket_limit(limit) for limit in value)
    if normalized != CAPTCHA_BUCKET_LIMITS_V1:
        _reject()
    return normalized


def _require_canonical_text(
    value: object,
    *,
    length: int,
    alphabet: frozenset[str],
) -> str:
    if type(value) is not str or len(value) != length or not value.isascii():
        _reject()
    for character in value:
        if character not in alphabet:
            _reject()
    return value


def validate_captcha_identifier_text_v1(
    value: object,
) -> CaptchaIdentifierShapeV1:
    """Validate strict challenge identifier text and return no identifier."""

    text = _require_canonical_text(
        value,
        length=CAPTCHA_IDENTIFIER_ENCODED_LENGTH,
        alphabet=CAPTCHA_IDENTIFIER_ALPHABET,
    )
    try:
        decoded = base64.urlsafe_b64decode(text + "==")
    except (binascii.Error, ValueError):
        _reject()
    if len(decoded) != CAPTCHA_IDENTIFIER_RAW_BYTES:
        _reject()
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != text:
        _reject()
    return CaptchaIdentifierShapeV1(
        raw_size_bytes=CAPTCHA_IDENTIFIER_RAW_BYTES,
        encoded_length=CAPTCHA_IDENTIFIER_ENCODED_LENGTH,
        alphabet=CAPTCHA_IDENTIFIER_ALPHABET,
    )


def validate_captcha_answer_text_v1(value: object) -> CaptchaAnswerShapeV1:
    """Validate strict candidate answer text and return no answer."""

    _require_canonical_text(
        value,
        length=CAPTCHA_ANSWER_LENGTH,
        alphabet=CAPTCHA_ANSWER_ALPHABET,
    )
    return CaptchaAnswerShapeV1(
        answer_length=CAPTCHA_ANSWER_LENGTH,
        alphabet=CAPTCHA_ANSWER_ALPHABET,
    )


def validate_captcha_identifier_shape_v1(
    shape: CaptchaIdentifierShapeV1,
) -> CaptchaIdentifierShapeV1:
    if type(shape) is not CaptchaIdentifierShapeV1:
        _reject()
    return CaptchaIdentifierShapeV1(
        raw_size_bytes=_require_uint_exact(
            shape.raw_size_bytes,
            expected=CAPTCHA_IDENTIFIER_RAW_BYTES,
        ),
        encoded_length=_require_uint_exact(
            shape.encoded_length,
            expected=CAPTCHA_IDENTIFIER_ENCODED_LENGTH,
        ),
        alphabet=_require_frozenset_exact(
            shape.alphabet,
            expected=CAPTCHA_IDENTIFIER_ALPHABET,
        ),
    )


def validate_captcha_answer_shape_v1(
    shape: CaptchaAnswerShapeV1,
) -> CaptchaAnswerShapeV1:
    if type(shape) is not CaptchaAnswerShapeV1:
        _reject()
    return CaptchaAnswerShapeV1(
        answer_length=_require_uint_exact(
            shape.answer_length,
            expected=CAPTCHA_ANSWER_LENGTH,
        ),
        alphabet=_require_frozenset_exact(
            shape.alphabet,
            expected=CAPTCHA_ANSWER_ALPHABET,
        ),
    )


def validate_captcha_form_scope_shape_v1(
    shape: CaptchaFormScopeShapeV1,
) -> CaptchaFormScopeShapeV1:
    if type(shape) is not CaptchaFormScopeShapeV1:
        _reject()
    return CaptchaFormScopeShapeV1(
        raw_size_bytes=_require_uint_exact(
            shape.raw_size_bytes,
            expected=CAPTCHA_FORM_SCOPE_RAW_BYTES,
        ),
    )


def validate_captcha_timing_profile_v1(
    profile: CaptchaTimingProfileV1,
) -> CaptchaTimingProfileV1:
    if type(profile) is not CaptchaTimingProfileV1:
        _reject()
    return CaptchaTimingProfileV1(
        expiry_seconds=_require_uint_exact(
            profile.expiry_seconds,
            expected=CAPTCHA_EXPIRY_SECONDS,
        ),
        cleanup_after_seconds=_require_uint_exact(
            profile.cleanup_after_seconds,
            expected=CAPTCHA_CLEANUP_AFTER_SECONDS,
        ),
    )


def validate_captcha_state_profile_v1(
    profile: CaptchaStateProfileV1,
) -> CaptchaStateProfileV1:
    if type(profile) is not CaptchaStateProfileV1:
        _reject()
    return CaptchaStateProfileV1(
        allowed_states=_require_state_sequence(profile.allowed_states),
    )


def validate_captcha_purpose_profile_v1(
    profile: CaptchaPurposeProfileV1,
) -> CaptchaPurposeProfileV1:
    if type(profile) is not CaptchaPurposeProfileV1:
        _reject()
    return CaptchaPurposeProfileV1(
        allowed_purposes=_require_purpose_sequence(profile.allowed_purposes),
    )


def validate_captcha_representation_profile_v1(
    profile: CaptchaRepresentationProfileV1,
) -> CaptchaRepresentationProfileV1:
    if type(profile) is not CaptchaRepresentationProfileV1:
        _reject()
    return CaptchaRepresentationProfileV1(
        png_width_pixels=_require_uint_exact(
            profile.png_width_pixels,
            expected=CAPTCHA_PNG_WIDTH_PIXELS,
        ),
        png_height_pixels=_require_uint_exact(
            profile.png_height_pixels,
            expected=CAPTCHA_PNG_HEIGHT_PIXELS,
        ),
        png_max_bytes=_require_uint_exact(
            profile.png_max_bytes,
            expected=CAPTCHA_PNG_MAX_BYTES,
        ),
        audio_required_before_production=_require_bool_exact(
            profile.audio_required_before_production,
            expected=True,
        ),
    )


def validate_captcha_abuse_control_profile_v1(
    profile: CaptchaAbuseControlProfileV1,
) -> CaptchaAbuseControlProfileV1:
    if type(profile) is not CaptchaAbuseControlProfileV1:
        _reject()
    return CaptchaAbuseControlProfileV1(
        bucket_limits=_require_bucket_limits(profile.bucket_limits),
        uses_network_identity_keys=_require_bool_exact(
            profile.uses_network_identity_keys,
            expected=False,
        ),
    )


def validate_captcha_production_gate_profile_v1(
    profile: CaptchaProductionGateProfileV1,
) -> CaptchaProductionGateProfileV1:
    if type(profile) is not CaptchaProductionGateProfileV1:
        _reject()
    return CaptchaProductionGateProfileV1(
        open_gates=_require_gate_sequence(profile.open_gates),
        production_enabled=_require_bool_exact(
            profile.production_enabled,
            expected=False,
        ),
    )


def validate_captcha_protocol_profile_v1(
    profile: CaptchaProtocolProfileV1,
) -> StructurallyValidCaptchaProtocolProfileV1:
    if type(profile) is not CaptchaProtocolProfileV1:
        _reject()
    normalized = CaptchaProtocolProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=CAPTCHA_PROTOCOL_VERSION,
        ),
        identifier_shape=validate_captcha_identifier_shape_v1(
            profile.identifier_shape
        ),
        answer_shape=validate_captcha_answer_shape_v1(profile.answer_shape),
        form_scope_shape=validate_captcha_form_scope_shape_v1(
            profile.form_scope_shape
        ),
        timing_profile=validate_captcha_timing_profile_v1(
            profile.timing_profile
        ),
        state_profile=validate_captcha_state_profile_v1(profile.state_profile),
        purpose_profile=validate_captcha_purpose_profile_v1(
            profile.purpose_profile
        ),
        representation_profile=validate_captcha_representation_profile_v1(
            profile.representation_profile
        ),
        abuse_control_profile=validate_captcha_abuse_control_profile_v1(
            profile.abuse_control_profile
        ),
        production_gate_profile=validate_captcha_production_gate_profile_v1(
            profile.production_gate_profile
        ),
    )
    return StructurallyValidCaptchaProtocolProfileV1(profile=normalized)


def expected_captcha_protocol_profile_v1() -> CaptchaProtocolProfileV1:
    """Return only the approved no-JavaScript CAPTCHA metadata."""

    return CaptchaProtocolProfileV1(
        scheme_version=CAPTCHA_PROTOCOL_VERSION,
        identifier_shape=CaptchaIdentifierShapeV1(
            raw_size_bytes=CAPTCHA_IDENTIFIER_RAW_BYTES,
            encoded_length=CAPTCHA_IDENTIFIER_ENCODED_LENGTH,
            alphabet=CAPTCHA_IDENTIFIER_ALPHABET,
        ),
        answer_shape=CaptchaAnswerShapeV1(
            answer_length=CAPTCHA_ANSWER_LENGTH,
            alphabet=CAPTCHA_ANSWER_ALPHABET,
        ),
        form_scope_shape=CaptchaFormScopeShapeV1(
            raw_size_bytes=CAPTCHA_FORM_SCOPE_RAW_BYTES,
        ),
        timing_profile=CaptchaTimingProfileV1(
            expiry_seconds=CAPTCHA_EXPIRY_SECONDS,
            cleanup_after_seconds=CAPTCHA_CLEANUP_AFTER_SECONDS,
        ),
        state_profile=CaptchaStateProfileV1(
            allowed_states=CAPTCHA_CHALLENGE_STATES_V1,
        ),
        purpose_profile=CaptchaPurposeProfileV1(
            allowed_purposes=CAPTCHA_PURPOSES_V1,
        ),
        representation_profile=CaptchaRepresentationProfileV1(
            png_width_pixels=CAPTCHA_PNG_WIDTH_PIXELS,
            png_height_pixels=CAPTCHA_PNG_HEIGHT_PIXELS,
            png_max_bytes=CAPTCHA_PNG_MAX_BYTES,
            audio_required_before_production=True,
        ),
        abuse_control_profile=CaptchaAbuseControlProfileV1(
            bucket_limits=CAPTCHA_BUCKET_LIMITS_V1,
            uses_network_identity_keys=False,
        ),
        production_gate_profile=CaptchaProductionGateProfileV1(
            open_gates=CAPTCHA_PRODUCTION_GATES_V1,
            production_enabled=False,
        ),
    )
