"""Inert Recovery Verifier key lifecycle descriptors from docs/21.

This module validates only static key-size, key-state, separation, storage
location, and lifecycle metadata for the approved Recovery Verifier key domain.
It does not generate keys, store keys, select request keys, rotate keys,
destroy keys, rewrite verifier records, call a Key Service, expose endpoints,
authorize Response-DEK use, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryKeyLifecycleDescriptorRejected


RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION = 1
RECOVERY_VERIFIER_KEY_BYTES = 32


class RecoveryVerifierKeyState(StrEnum):
    ACTIVE_FOR_CREATION = "ACTIVE_FOR_CREATION"
    RETIRED_VERIFY_ONLY = "RETIRED_VERIFY_ONLY"
    DESTROYED_AFTER_NO_ELIGIBLE_REFERENCES = (
        "DESTROYED_AFTER_NO_ELIGIBLE_REFERENCES"
    )


class RecoveryVerifierKeySeparation(StrEnum):
    DJANGO_SECRET_KEY = "DJANGO_SECRET_KEY"
    REPORT_DEK = "REPORT_DEK"
    RESPONSE_DEK = "RESPONSE_DEK"
    ENCRYPTION_KEY = "ENCRYPTION_KEY"
    WRAPPING_KEY = "WRAPPING_KEY"
    AUDIT_KEY = "AUDIT_KEY"
    EXPORT_KEY = "EXPORT_KEY"
    TLS_KEY = "TLS_KEY"
    CAPTCHA_KEY = "CAPTCHA_KEY"
    CSRF_KEY = "CSRF_KEY"
    SESSION_KEY = "SESSION_KEY"
    SERVICE_AUTHENTICATION_KEY = "SERVICE_AUTHENTICATION_KEY"


class RecoveryVerifierKeyForbiddenLocation(StrEnum):
    SOURCE_CODE = "SOURCE_CODE"
    DJANGO_SETTINGS = "DJANGO_SETTINGS"
    APPLICATION_DATABASE = "APPLICATION_DATABASE"
    APPLICATION_LOG = "APPLICATION_LOG"
    AUDIT_EVENT = "AUDIT_EVENT"
    BROWSER_STORAGE = "BROWSER_STORAGE"
    REPORTER_RESPONSE = "REPORTER_RESPONSE"


class RecoveryVerifierKeyLifecycleRequirement(StrEnum):
    SERVICE_SELECTED_KEY_ID = "SERVICE_SELECTED_KEY_ID"
    ONE_ACTIVE_CREATION_VERSION = "ONE_ACTIVE_CREATION_VERSION"
    RETIRED_VERIFY_ONLY = "RETIRED_VERIFY_ONLY"
    NO_SILENT_VERSION_FALLBACK = "NO_SILENT_VERSION_FALLBACK"
    DESTROY_AFTER_NO_ELIGIBLE_RECORDS = "DESTROY_AFTER_NO_ELIGIBLE_RECORDS"
    RESTORE_PROOF_BEFORE_DESTRUCTION = "RESTORE_PROOF_BEFORE_DESTRUCTION"
    LOSS_FAILS_CLOSED = "LOSS_FAILS_CLOSED"
    NO_RESPONSE_DEK_AUTHORITY = "NO_RESPONSE_DEK_AUTHORITY"


RECOVERY_VERIFIER_KEY_STATES_V1 = (
    RecoveryVerifierKeyState.ACTIVE_FOR_CREATION,
    RecoveryVerifierKeyState.RETIRED_VERIFY_ONLY,
    RecoveryVerifierKeyState.DESTROYED_AFTER_NO_ELIGIBLE_REFERENCES,
)

RECOVERY_VERIFIER_KEY_SEPARATIONS_V1 = (
    RecoveryVerifierKeySeparation.DJANGO_SECRET_KEY,
    RecoveryVerifierKeySeparation.REPORT_DEK,
    RecoveryVerifierKeySeparation.RESPONSE_DEK,
    RecoveryVerifierKeySeparation.ENCRYPTION_KEY,
    RecoveryVerifierKeySeparation.WRAPPING_KEY,
    RecoveryVerifierKeySeparation.AUDIT_KEY,
    RecoveryVerifierKeySeparation.EXPORT_KEY,
    RecoveryVerifierKeySeparation.TLS_KEY,
    RecoveryVerifierKeySeparation.CAPTCHA_KEY,
    RecoveryVerifierKeySeparation.CSRF_KEY,
    RecoveryVerifierKeySeparation.SESSION_KEY,
    RecoveryVerifierKeySeparation.SERVICE_AUTHENTICATION_KEY,
)

RECOVERY_VERIFIER_KEY_FORBIDDEN_LOCATIONS_V1 = (
    RecoveryVerifierKeyForbiddenLocation.SOURCE_CODE,
    RecoveryVerifierKeyForbiddenLocation.DJANGO_SETTINGS,
    RecoveryVerifierKeyForbiddenLocation.APPLICATION_DATABASE,
    RecoveryVerifierKeyForbiddenLocation.APPLICATION_LOG,
    RecoveryVerifierKeyForbiddenLocation.AUDIT_EVENT,
    RecoveryVerifierKeyForbiddenLocation.BROWSER_STORAGE,
    RecoveryVerifierKeyForbiddenLocation.REPORTER_RESPONSE,
)

RECOVERY_VERIFIER_KEY_LIFECYCLE_REQUIREMENTS_V1 = (
    RecoveryVerifierKeyLifecycleRequirement.SERVICE_SELECTED_KEY_ID,
    RecoveryVerifierKeyLifecycleRequirement.ONE_ACTIVE_CREATION_VERSION,
    RecoveryVerifierKeyLifecycleRequirement.RETIRED_VERIFY_ONLY,
    RecoveryVerifierKeyLifecycleRequirement.NO_SILENT_VERSION_FALLBACK,
    RecoveryVerifierKeyLifecycleRequirement.DESTROY_AFTER_NO_ELIGIBLE_RECORDS,
    RecoveryVerifierKeyLifecycleRequirement.RESTORE_PROOF_BEFORE_DESTRUCTION,
    RecoveryVerifierKeyLifecycleRequirement.LOSS_FAILS_CLOSED,
    RecoveryVerifierKeyLifecycleRequirement.NO_RESPONSE_DEK_AUTHORITY,
)


@dataclass(frozen=True, slots=True)
class RecoveryVerifierKeySizeProfileV1:
    key_size_bytes: int


@dataclass(frozen=True, slots=True)
class RecoveryVerifierKeyStateProfileV1:
    states: tuple[RecoveryVerifierKeyState, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierKeySeparationProfileV1:
    separated_from: tuple[RecoveryVerifierKeySeparation, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierKeyLocationPolicyV1:
    forbidden_locations: tuple[RecoveryVerifierKeyForbiddenLocation, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierKeyLifecycleRequirementProfileV1:
    requirements: tuple[RecoveryVerifierKeyLifecycleRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierKeyLifecycleProfileV1:
    scheme_version: int
    key_size: RecoveryVerifierKeySizeProfileV1
    states: RecoveryVerifierKeyStateProfileV1
    separation: RecoveryVerifierKeySeparationProfileV1
    location_policy: RecoveryVerifierKeyLocationPolicyV1
    requirements: RecoveryVerifierKeyLifecycleRequirementProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryVerifierKeyLifecycleProfileV1:
    profile: RecoveryVerifierKeyLifecycleProfileV1

    @property
    def generates_key(self) -> bool:
        return False

    @property
    def stores_key(self) -> bool:
        return False

    @property
    def selects_key_for_request(self) -> bool:
        return False

    @property
    def rotates_key(self) -> bool:
        return False

    @property
    def destroys_key(self) -> bool:
        return False

    @property
    def rewrites_verifier(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def authorizes_response_dek_use(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryKeyLifecycleDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_key_state(value: object) -> RecoveryVerifierKeyState:
    if isinstance(value, RecoveryVerifierKeyState):
        return value
    _reject()


def _require_key_separation(value: object) -> RecoveryVerifierKeySeparation:
    if isinstance(value, RecoveryVerifierKeySeparation):
        return value
    _reject()


def _require_forbidden_location(
    value: object,
) -> RecoveryVerifierKeyForbiddenLocation:
    if isinstance(value, RecoveryVerifierKeyForbiddenLocation):
        return value
    _reject()


def _require_lifecycle_requirement(
    value: object,
) -> RecoveryVerifierKeyLifecycleRequirement:
    if isinstance(value, RecoveryVerifierKeyLifecycleRequirement):
        return value
    _reject()


def _require_key_states(
    value: object,
) -> tuple[RecoveryVerifierKeyState, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_key_state(item) for item in value)
    if normalized != RECOVERY_VERIFIER_KEY_STATES_V1:
        _reject()
    return normalized


def _require_key_separations(
    value: object,
) -> tuple[RecoveryVerifierKeySeparation, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_key_separation(item) for item in value)
    if normalized != RECOVERY_VERIFIER_KEY_SEPARATIONS_V1:
        _reject()
    return normalized


def _require_forbidden_locations(
    value: object,
) -> tuple[RecoveryVerifierKeyForbiddenLocation, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_location(item) for item in value)
    if normalized != RECOVERY_VERIFIER_KEY_FORBIDDEN_LOCATIONS_V1:
        _reject()
    return normalized


def _require_lifecycle_requirements(
    value: object,
) -> tuple[RecoveryVerifierKeyLifecycleRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_lifecycle_requirement(item) for item in value)
    if normalized != RECOVERY_VERIFIER_KEY_LIFECYCLE_REQUIREMENTS_V1:
        _reject()
    return normalized


def validate_recovery_verifier_key_size_profile_v1(
    profile: RecoveryVerifierKeySizeProfileV1,
) -> RecoveryVerifierKeySizeProfileV1:
    if type(profile) is not RecoveryVerifierKeySizeProfileV1:
        _reject()
    normalized = RecoveryVerifierKeySizeProfileV1(
        key_size_bytes=_require_uint_exact(
            profile.key_size_bytes,
            expected=RECOVERY_VERIFIER_KEY_BYTES,
        )
    )
    if normalized != expected_recovery_verifier_key_size_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_key_state_profile_v1(
    profile: RecoveryVerifierKeyStateProfileV1,
) -> RecoveryVerifierKeyStateProfileV1:
    if type(profile) is not RecoveryVerifierKeyStateProfileV1:
        _reject()
    normalized = RecoveryVerifierKeyStateProfileV1(
        states=_require_key_states(profile.states)
    )
    if normalized != expected_recovery_verifier_key_state_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_key_separation_profile_v1(
    profile: RecoveryVerifierKeySeparationProfileV1,
) -> RecoveryVerifierKeySeparationProfileV1:
    if type(profile) is not RecoveryVerifierKeySeparationProfileV1:
        _reject()
    normalized = RecoveryVerifierKeySeparationProfileV1(
        separated_from=_require_key_separations(profile.separated_from)
    )
    if normalized != expected_recovery_verifier_key_separation_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_key_location_policy_v1(
    profile: RecoveryVerifierKeyLocationPolicyV1,
) -> RecoveryVerifierKeyLocationPolicyV1:
    if type(profile) is not RecoveryVerifierKeyLocationPolicyV1:
        _reject()
    normalized = RecoveryVerifierKeyLocationPolicyV1(
        forbidden_locations=_require_forbidden_locations(
            profile.forbidden_locations
        )
    )
    if normalized != expected_recovery_verifier_key_location_policy_v1():
        _reject()
    return normalized


def validate_recovery_verifier_key_lifecycle_requirement_profile_v1(
    profile: RecoveryVerifierKeyLifecycleRequirementProfileV1,
) -> RecoveryVerifierKeyLifecycleRequirementProfileV1:
    if type(profile) is not RecoveryVerifierKeyLifecycleRequirementProfileV1:
        _reject()
    normalized = RecoveryVerifierKeyLifecycleRequirementProfileV1(
        requirements=_require_lifecycle_requirements(profile.requirements)
    )
    if normalized != expected_recovery_verifier_key_lifecycle_requirement_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_key_lifecycle_profile_v1(
    profile: RecoveryVerifierKeyLifecycleProfileV1,
) -> StructurallyValidRecoveryVerifierKeyLifecycleProfileV1:
    if type(profile) is not RecoveryVerifierKeyLifecycleProfileV1:
        _reject()
    normalized = RecoveryVerifierKeyLifecycleProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION,
        ),
        key_size=validate_recovery_verifier_key_size_profile_v1(
            profile.key_size
        ),
        states=validate_recovery_verifier_key_state_profile_v1(profile.states),
        separation=validate_recovery_verifier_key_separation_profile_v1(
            profile.separation
        ),
        location_policy=validate_recovery_verifier_key_location_policy_v1(
            profile.location_policy
        ),
        requirements=(
            validate_recovery_verifier_key_lifecycle_requirement_profile_v1(
                profile.requirements
            )
        ),
    )
    if normalized != expected_recovery_verifier_key_lifecycle_profile_v1():
        _reject()
    return StructurallyValidRecoveryVerifierKeyLifecycleProfileV1(normalized)


def expected_recovery_verifier_key_size_profile_v1(
) -> RecoveryVerifierKeySizeProfileV1:
    return RecoveryVerifierKeySizeProfileV1(
        key_size_bytes=RECOVERY_VERIFIER_KEY_BYTES
    )


def expected_recovery_verifier_key_state_profile_v1(
) -> RecoveryVerifierKeyStateProfileV1:
    return RecoveryVerifierKeyStateProfileV1(
        states=RECOVERY_VERIFIER_KEY_STATES_V1
    )


def expected_recovery_verifier_key_separation_profile_v1(
) -> RecoveryVerifierKeySeparationProfileV1:
    return RecoveryVerifierKeySeparationProfileV1(
        separated_from=RECOVERY_VERIFIER_KEY_SEPARATIONS_V1
    )


def expected_recovery_verifier_key_location_policy_v1(
) -> RecoveryVerifierKeyLocationPolicyV1:
    return RecoveryVerifierKeyLocationPolicyV1(
        forbidden_locations=RECOVERY_VERIFIER_KEY_FORBIDDEN_LOCATIONS_V1
    )


def expected_recovery_verifier_key_lifecycle_requirement_profile_v1(
) -> RecoveryVerifierKeyLifecycleRequirementProfileV1:
    return RecoveryVerifierKeyLifecycleRequirementProfileV1(
        requirements=RECOVERY_VERIFIER_KEY_LIFECYCLE_REQUIREMENTS_V1
    )


def expected_recovery_verifier_key_lifecycle_profile_v1(
) -> RecoveryVerifierKeyLifecycleProfileV1:
    return RecoveryVerifierKeyLifecycleProfileV1(
        scheme_version=RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION,
        key_size=expected_recovery_verifier_key_size_profile_v1(),
        states=expected_recovery_verifier_key_state_profile_v1(),
        separation=expected_recovery_verifier_key_separation_profile_v1(),
        location_policy=expected_recovery_verifier_key_location_policy_v1(),
        requirements=(
            expected_recovery_verifier_key_lifecycle_requirement_profile_v1()
        ),
    )
