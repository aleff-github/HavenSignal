"""Inert recovery eligibility descriptors from docs/05, docs/24, and docs/32.

This module validates only static eligibility metadata for the approved
Recovery Gateway, State Authority, and Key Service boundary. It does not
perform ticket lookup, validate credentials, validate CAPTCHA, call the
Recovery Verifier Service, call the Key Service, read ciphertext, decrypt a
Response Note, mutate first-read state, destroy keys, invalidate recovery
state, expose endpoints, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryEligibilityDescriptorRejected


RECOVERY_ELIGIBILITY_PROFILE_VERSION = 1
RECOVERY_FIRST_READ_EXPIRY_SECONDS = 72 * 60 * 60
RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS = 90 * 24 * 60 * 60


class RecoveryEligibilityState(StrEnum):
    RESPONSE_UNAVAILABLE = "RESPONSE_UNAVAILABLE"
    RESPONSE_AVAILABLE_UNREAD = "RESPONSE_AVAILABLE_UNREAD"
    READ_WINDOW_OPEN = "READ_WINDOW_OPEN"
    READ_WINDOW_EXPIRED = "READ_WINDOW_EXPIRED"
    NEVER_READ_EXPIRED = "NEVER_READ_EXPIRED"
    RESPONSE_DESTROYED = "RESPONSE_DESTROYED"


class RecoveryEligibilityRequirement(StrEnum):
    POST_CREDENTIALS_AND_CAPTCHA_REQUIRED = (
        "POST_CREDENTIALS_AND_CAPTCHA_REQUIRED"
    )
    SERVER_AUTHORITATIVE_STATE = "SERVER_AUTHORITATIVE_STATE"
    VERIFIER_SUCCESS_NOT_SUFFICIENT = "VERIFIER_SUCCESS_NOT_SUFFICIENT"
    RESPONSE_DEK_AUTHORIZATION_REQUIRED = "RESPONSE_DEK_AUTHORIZATION_REQUIRED"
    ORIGINAL_REPORT_KEY_DESTROYED_BEFORE_VISIBLE = (
        "ORIGINAL_REPORT_KEY_DESTROYED_BEFORE_VISIBLE"
    )
    UNREAD_EXPIRY_FIXED_AT_RESPONSE_AVAILABLE = (
        "UNREAD_EXPIRY_FIXED_AT_RESPONSE_AVAILABLE"
    )
    EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT = (
        "EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT"
    )
    FIRST_READ_EXPIRY_NON_EXTENDING = "FIRST_READ_EXPIRY_NON_EXTENDING"
    DENY_AFTER_SERVER_AUTHORITATIVE_EXPIRY = (
        "DENY_AFTER_SERVER_AUTHORITATIVE_EXPIRY"
    )
    INVALIDATE_RECOVERY_STATE_AT_EXPIRY = (
        "INVALIDATE_RECOVERY_STATE_AT_EXPIRY"
    )
    GENERIC_NON_SUCCESS_FOR_INELIGIBLE_STATE = (
        "GENERIC_NON_SUCCESS_FOR_INELIGIBLE_STATE"
    )


class RecoveryEligibilityForbiddenCapability(StrEnum):
    PERFORMS_LOOKUP = "PERFORMS_LOOKUP"
    VALIDATES_CREDENTIALS = "VALIDATES_CREDENTIALS"
    VALIDATES_CAPTCHA = "VALIDATES_CAPTCHA"
    CALLS_VERIFIER_SERVICE = "CALLS_VERIFIER_SERVICE"
    CALLS_KEY_SERVICE = "CALLS_KEY_SERVICE"
    READS_RESPONSE_STATE = "READS_RESPONSE_STATE"
    READS_RESPONSE_CIPHERTEXT = "READS_RESPONSE_CIPHERTEXT"
    DECRYPTS_RESPONSE = "DECRYPTS_RESPONSE"
    MUTATES_FIRST_READ = "MUTATES_FIRST_READ"
    DESTROYS_RESPONSE_DEK = "DESTROYS_RESPONSE_DEK"
    INVALIDATES_RECOVERY_STATE = "INVALIDATES_RECOVERY_STATE"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_RECOVERY = "AUTHORIZES_RECOVERY"
    EXTENDS_RESPONSE_WINDOW = "EXTENDS_RESPONSE_WINDOW"
    LOGS_CREDENTIALS = "LOGS_CREDENTIALS"
    RETURNS_DISTINCT_FAILURE = "RETURNS_DISTINCT_FAILURE"


RECOVERY_ELIGIBILITY_STATES_V1 = (
    RecoveryEligibilityState.RESPONSE_UNAVAILABLE,
    RecoveryEligibilityState.RESPONSE_AVAILABLE_UNREAD,
    RecoveryEligibilityState.READ_WINDOW_OPEN,
    RecoveryEligibilityState.READ_WINDOW_EXPIRED,
    RecoveryEligibilityState.NEVER_READ_EXPIRED,
    RecoveryEligibilityState.RESPONSE_DESTROYED,
)

RECOVERY_ELIGIBILITY_REQUIREMENTS_V1 = (
    RecoveryEligibilityRequirement.POST_CREDENTIALS_AND_CAPTCHA_REQUIRED,
    RecoveryEligibilityRequirement.SERVER_AUTHORITATIVE_STATE,
    RecoveryEligibilityRequirement.VERIFIER_SUCCESS_NOT_SUFFICIENT,
    RecoveryEligibilityRequirement.RESPONSE_DEK_AUTHORIZATION_REQUIRED,
    RecoveryEligibilityRequirement.ORIGINAL_REPORT_KEY_DESTROYED_BEFORE_VISIBLE,
    RecoveryEligibilityRequirement.UNREAD_EXPIRY_FIXED_AT_RESPONSE_AVAILABLE,
    RecoveryEligibilityRequirement.EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT,
    RecoveryEligibilityRequirement.FIRST_READ_EXPIRY_NON_EXTENDING,
    RecoveryEligibilityRequirement.DENY_AFTER_SERVER_AUTHORITATIVE_EXPIRY,
    RecoveryEligibilityRequirement.INVALIDATE_RECOVERY_STATE_AT_EXPIRY,
    RecoveryEligibilityRequirement.GENERIC_NON_SUCCESS_FOR_INELIGIBLE_STATE,
)

RECOVERY_ELIGIBILITY_FORBIDDEN_CAPABILITIES_V1 = (
    RecoveryEligibilityForbiddenCapability.PERFORMS_LOOKUP,
    RecoveryEligibilityForbiddenCapability.VALIDATES_CREDENTIALS,
    RecoveryEligibilityForbiddenCapability.VALIDATES_CAPTCHA,
    RecoveryEligibilityForbiddenCapability.CALLS_VERIFIER_SERVICE,
    RecoveryEligibilityForbiddenCapability.CALLS_KEY_SERVICE,
    RecoveryEligibilityForbiddenCapability.READS_RESPONSE_STATE,
    RecoveryEligibilityForbiddenCapability.READS_RESPONSE_CIPHERTEXT,
    RecoveryEligibilityForbiddenCapability.DECRYPTS_RESPONSE,
    RecoveryEligibilityForbiddenCapability.MUTATES_FIRST_READ,
    RecoveryEligibilityForbiddenCapability.DESTROYS_RESPONSE_DEK,
    RecoveryEligibilityForbiddenCapability.INVALIDATES_RECOVERY_STATE,
    RecoveryEligibilityForbiddenCapability.EXPOSES_ENDPOINT,
    RecoveryEligibilityForbiddenCapability.AUTHORIZES_RECOVERY,
    RecoveryEligibilityForbiddenCapability.EXTENDS_RESPONSE_WINDOW,
    RecoveryEligibilityForbiddenCapability.LOGS_CREDENTIALS,
    RecoveryEligibilityForbiddenCapability.RETURNS_DISTINCT_FAILURE,
)


@dataclass(frozen=True, slots=True)
class RecoveryEligibilityStateProfileV1:
    states: tuple[RecoveryEligibilityState, ...]


@dataclass(frozen=True, slots=True)
class RecoveryEligibilityTimingProfileV1:
    first_read_expiry_seconds: int
    unread_response_expiry_seconds: int


@dataclass(frozen=True, slots=True)
class RecoveryEligibilityRequirementProfileV1:
    requirements: tuple[RecoveryEligibilityRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryEligibilityCapabilityDenialProfileV1:
    forbidden_capabilities: tuple[RecoveryEligibilityForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class RecoveryEligibilityProfileV1:
    scheme_version: int
    states: RecoveryEligibilityStateProfileV1
    timing: RecoveryEligibilityTimingProfileV1
    requirements: RecoveryEligibilityRequirementProfileV1
    capability_denials: RecoveryEligibilityCapabilityDenialProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryEligibilityProfileV1:
    profile: RecoveryEligibilityProfileV1

    @property
    def performs_lookup(self) -> bool:
        return False

    @property
    def validates_credentials(self) -> bool:
        return False

    @property
    def validates_captcha(self) -> bool:
        return False

    @property
    def calls_verifier_service(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def reads_response_state(self) -> bool:
        return False

    @property
    def reads_response_ciphertext(self) -> bool:
        return False

    @property
    def decrypts_response(self) -> bool:
        return False

    @property
    def mutates_first_read(self) -> bool:
        return False

    @property
    def destroys_response_dek(self) -> bool:
        return False

    @property
    def invalidates_recovery_state(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False

    @property
    def extends_response_window(self) -> bool:
        return False

    @property
    def logs_credentials(self) -> bool:
        return False

    @property
    def returns_distinct_failure(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryEligibilityDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_state(value: object) -> RecoveryEligibilityState:
    if isinstance(value, RecoveryEligibilityState):
        return value
    _reject()


def _require_requirement(value: object) -> RecoveryEligibilityRequirement:
    if isinstance(value, RecoveryEligibilityRequirement):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> RecoveryEligibilityForbiddenCapability:
    if isinstance(value, RecoveryEligibilityForbiddenCapability):
        return value
    _reject()


def _require_states(value: object) -> tuple[RecoveryEligibilityState, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_state(item) for item in value)
    if normalized != RECOVERY_ELIGIBILITY_STATES_V1:
        _reject()
    return normalized


def _require_requirements(
    value: object,
) -> tuple[RecoveryEligibilityRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_requirement(item) for item in value)
    if normalized != RECOVERY_ELIGIBILITY_REQUIREMENTS_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[RecoveryEligibilityForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != RECOVERY_ELIGIBILITY_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


def validate_recovery_eligibility_state_profile_v1(
    profile: RecoveryEligibilityStateProfileV1,
) -> RecoveryEligibilityStateProfileV1:
    if type(profile) is not RecoveryEligibilityStateProfileV1:
        _reject()
    normalized = RecoveryEligibilityStateProfileV1(
        states=_require_states(profile.states)
    )
    if normalized != expected_recovery_eligibility_state_profile_v1():
        _reject()
    return normalized


def validate_recovery_eligibility_timing_profile_v1(
    profile: RecoveryEligibilityTimingProfileV1,
) -> RecoveryEligibilityTimingProfileV1:
    if type(profile) is not RecoveryEligibilityTimingProfileV1:
        _reject()
    normalized = RecoveryEligibilityTimingProfileV1(
        first_read_expiry_seconds=_require_uint_exact(
            profile.first_read_expiry_seconds,
            expected=RECOVERY_FIRST_READ_EXPIRY_SECONDS,
        ),
        unread_response_expiry_seconds=_require_uint_exact(
            profile.unread_response_expiry_seconds,
            expected=RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS,
        ),
    )
    if normalized != expected_recovery_eligibility_timing_profile_v1():
        _reject()
    return normalized


def validate_recovery_eligibility_requirement_profile_v1(
    profile: RecoveryEligibilityRequirementProfileV1,
) -> RecoveryEligibilityRequirementProfileV1:
    if type(profile) is not RecoveryEligibilityRequirementProfileV1:
        _reject()
    normalized = RecoveryEligibilityRequirementProfileV1(
        requirements=_require_requirements(profile.requirements)
    )
    if normalized != expected_recovery_eligibility_requirement_profile_v1():
        _reject()
    return normalized


def validate_recovery_eligibility_capability_denial_profile_v1(
    profile: RecoveryEligibilityCapabilityDenialProfileV1,
) -> RecoveryEligibilityCapabilityDenialProfileV1:
    if type(profile) is not RecoveryEligibilityCapabilityDenialProfileV1:
        _reject()
    normalized = RecoveryEligibilityCapabilityDenialProfileV1(
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        )
    )
    if normalized != expected_recovery_eligibility_capability_denial_profile_v1():
        _reject()
    return normalized


def validate_recovery_eligibility_profile_v1(
    profile: RecoveryEligibilityProfileV1,
) -> StructurallyValidRecoveryEligibilityProfileV1:
    if type(profile) is not RecoveryEligibilityProfileV1:
        _reject()
    normalized = RecoveryEligibilityProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_ELIGIBILITY_PROFILE_VERSION,
        ),
        states=validate_recovery_eligibility_state_profile_v1(profile.states),
        timing=validate_recovery_eligibility_timing_profile_v1(profile.timing),
        requirements=validate_recovery_eligibility_requirement_profile_v1(
            profile.requirements
        ),
        capability_denials=(
            validate_recovery_eligibility_capability_denial_profile_v1(
                profile.capability_denials
            )
        ),
    )
    if normalized != expected_recovery_eligibility_profile_v1():
        _reject()
    return StructurallyValidRecoveryEligibilityProfileV1(normalized)


def expected_recovery_eligibility_state_profile_v1(
) -> RecoveryEligibilityStateProfileV1:
    return RecoveryEligibilityStateProfileV1(states=RECOVERY_ELIGIBILITY_STATES_V1)


def expected_recovery_eligibility_timing_profile_v1(
) -> RecoveryEligibilityTimingProfileV1:
    return RecoveryEligibilityTimingProfileV1(
        first_read_expiry_seconds=RECOVERY_FIRST_READ_EXPIRY_SECONDS,
        unread_response_expiry_seconds=RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS,
    )


def expected_recovery_eligibility_requirement_profile_v1(
) -> RecoveryEligibilityRequirementProfileV1:
    return RecoveryEligibilityRequirementProfileV1(
        requirements=RECOVERY_ELIGIBILITY_REQUIREMENTS_V1
    )


def expected_recovery_eligibility_capability_denial_profile_v1(
) -> RecoveryEligibilityCapabilityDenialProfileV1:
    return RecoveryEligibilityCapabilityDenialProfileV1(
        forbidden_capabilities=RECOVERY_ELIGIBILITY_FORBIDDEN_CAPABILITIES_V1
    )


def expected_recovery_eligibility_profile_v1() -> RecoveryEligibilityProfileV1:
    return RecoveryEligibilityProfileV1(
        scheme_version=RECOVERY_ELIGIBILITY_PROFILE_VERSION,
        states=expected_recovery_eligibility_state_profile_v1(),
        timing=expected_recovery_eligibility_timing_profile_v1(),
        requirements=expected_recovery_eligibility_requirement_profile_v1(),
        capability_denials=(
            expected_recovery_eligibility_capability_denial_profile_v1()
        ),
    )
