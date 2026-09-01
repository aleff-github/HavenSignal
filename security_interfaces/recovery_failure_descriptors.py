"""Inert recovery failure descriptors from docs/21.

This module validates only static failure-boundary and required-result
metadata for the approved recovery credential construction. It does not
generate randomness, decode credentials, call a verifier, compare HMAC tags,
read response state, call the Key Service, log credentials, expose endpoints,
or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryFailureDescriptorRejected


RECOVERY_FAILURE_PROFILE_VERSION = 1


class RecoveryFailureBoundary(StrEnum):
    RANDOM_SOURCE_UNAVAILABLE_OR_WRONG_LENGTH = (
        "RANDOM_SOURCE_UNAVAILABLE_OR_WRONG_LENGTH"
    )
    REPEATED_TICKET_ID_COLLISION = "REPEATED_TICKET_ID_COLLISION"
    ENCODING_MALFORMED_OR_NON_CANONICAL = "ENCODING_MALFORMED_OR_NON_CANONICAL"
    VERIFIER_SERVICE_OR_KEY_UNAVAILABLE = "VERIFIER_SERVICE_OR_KEY_UNAVAILABLE"
    UNKNOWN_VERSION_OR_KEY_IDENTIFIER = "UNKNOWN_VERSION_OR_KEY_IDENTIFIER"
    HMAC_MISMATCH = "HMAC_MISMATCH"
    CORRECT_CREDENTIALS_BUT_RESPONSE_UNAVAILABLE_EXPIRED_OR_DESTROYED = (
        "CORRECT_CREDENTIALS_BUT_RESPONSE_UNAVAILABLE_EXPIRED_OR_DESTROYED"
    )
    CONCURRENT_FIRST_READS = "CONCURRENT_FIRST_READS"
    RESPONSE_DEK_EXPIRED = "RESPONSE_DEK_EXPIRED"
    LOGGING_OR_TELEMETRY_ATTEMPTS_TO_INCLUDE_CREDENTIALS = (
        "LOGGING_OR_TELEMETRY_ATTEMPTS_TO_INCLUDE_CREDENTIALS"
    )


class RecoveryFailureRequiredResult(StrEnum):
    ABORT_BEFORE_ACCEPTANCE_NO_FALLBACK_GENERATOR = (
        "ABORT_BEFORE_ACCEPTANCE_NO_FALLBACK_GENERATOR"
    )
    ABORT_AFTER_THREE_FRESH_ID_ATTEMPTS_WITHOUT_ID_DISCLOSURE = (
        "ABORT_AFTER_THREE_FRESH_ID_ATTEMPTS_WITHOUT_ID_DISCLOSURE"
    )
    GENERIC_NON_SUCCESS_NO_LOOKUP_OR_ALTERNATE_DECODER = (
        "GENERIC_NON_SUCCESS_NO_LOOKUP_OR_ALTERNATE_DECODER"
    )
    GENERIC_NON_SUCCESS_NO_LOCAL_UNKEYED_OR_PLAINTEXT_FALLBACK = (
        "GENERIC_NON_SUCCESS_NO_LOCAL_UNKEYED_OR_PLAINTEXT_FALLBACK"
    )
    GENERIC_NON_SUCCESS_AND_CONTROLLED_INTERNAL_EVENT = (
        "GENERIC_NON_SUCCESS_AND_CONTROLLED_INTERNAL_EVENT"
    )
    GENERIC_NON_SUCCESS_NO_PARTIAL_MATCH_DETAIL = (
        "GENERIC_NON_SUCCESS_NO_PARTIAL_MATCH_DETAIL"
    )
    SAME_GENERIC_NON_SUCCESS = "SAME_GENERIC_NON_SUCCESS"
    EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT_AND_EXPIRY = (
        "EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT_AND_EXPIRY"
    )
    DENY_BEFORE_USE_WHILE_CLEANUP_RETRIES = (
        "DENY_BEFORE_USE_WHILE_CLEANUP_RETRIES"
    )
    REJECT_OR_REDACT_AT_SCHEMA_BOUNDARY_AND_FAIL_SECURITY_TEST = (
        "REJECT_OR_REDACT_AT_SCHEMA_BOUNDARY_AND_FAIL_SECURITY_TEST"
    )


class RecoveryFailureForbiddenCapability(StrEnum):
    GENERATES_RANDOMNESS = "GENERATES_RANDOMNESS"
    RETRIES_TICKET_ID_CREATION = "RETRIES_TICKET_ID_CREATION"
    DECODES_CREDENTIAL = "DECODES_CREDENTIAL"
    CALLS_VERIFIER_SERVICE = "CALLS_VERIFIER_SERVICE"
    COMPARES_HMAC_TAG = "COMPARES_HMAC_TAG"
    READS_RESPONSE_STATE = "READS_RESPONSE_STATE"
    CALLS_KEY_SERVICE = "CALLS_KEY_SERVICE"
    MUTATES_FIRST_READ = "MUTATES_FIRST_READ"
    LOGS_CREDENTIAL = "LOGS_CREDENTIAL"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_RECOVERY = "AUTHORIZES_RECOVERY"


RECOVERY_FAILURE_BOUNDARIES_V1 = (
    RecoveryFailureBoundary.RANDOM_SOURCE_UNAVAILABLE_OR_WRONG_LENGTH,
    RecoveryFailureBoundary.REPEATED_TICKET_ID_COLLISION,
    RecoveryFailureBoundary.ENCODING_MALFORMED_OR_NON_CANONICAL,
    RecoveryFailureBoundary.VERIFIER_SERVICE_OR_KEY_UNAVAILABLE,
    RecoveryFailureBoundary.UNKNOWN_VERSION_OR_KEY_IDENTIFIER,
    RecoveryFailureBoundary.HMAC_MISMATCH,
    (
        RecoveryFailureBoundary.
        CORRECT_CREDENTIALS_BUT_RESPONSE_UNAVAILABLE_EXPIRED_OR_DESTROYED
    ),
    RecoveryFailureBoundary.CONCURRENT_FIRST_READS,
    RecoveryFailureBoundary.RESPONSE_DEK_EXPIRED,
    (
        RecoveryFailureBoundary.
        LOGGING_OR_TELEMETRY_ATTEMPTS_TO_INCLUDE_CREDENTIALS
    ),
)

RECOVERY_FAILURE_REQUIRED_RESULTS_V1 = (
    RecoveryFailureRequiredResult.ABORT_BEFORE_ACCEPTANCE_NO_FALLBACK_GENERATOR,
    (
        RecoveryFailureRequiredResult.
        ABORT_AFTER_THREE_FRESH_ID_ATTEMPTS_WITHOUT_ID_DISCLOSURE
    ),
    (
        RecoveryFailureRequiredResult.
        GENERIC_NON_SUCCESS_NO_LOOKUP_OR_ALTERNATE_DECODER
    ),
    (
        RecoveryFailureRequiredResult.
        GENERIC_NON_SUCCESS_NO_LOCAL_UNKEYED_OR_PLAINTEXT_FALLBACK
    ),
    (
        RecoveryFailureRequiredResult.
        GENERIC_NON_SUCCESS_AND_CONTROLLED_INTERNAL_EVENT
    ),
    RecoveryFailureRequiredResult.GENERIC_NON_SUCCESS_NO_PARTIAL_MATCH_DETAIL,
    RecoveryFailureRequiredResult.SAME_GENERIC_NON_SUCCESS,
    RecoveryFailureRequiredResult.EXACTLY_ONE_IMMUTABLE_FIRST_READ_AT_AND_EXPIRY,
    RecoveryFailureRequiredResult.DENY_BEFORE_USE_WHILE_CLEANUP_RETRIES,
    (
        RecoveryFailureRequiredResult.
        REJECT_OR_REDACT_AT_SCHEMA_BOUNDARY_AND_FAIL_SECURITY_TEST
    ),
)

RECOVERY_FAILURE_FORBIDDEN_CAPABILITIES_V1 = (
    RecoveryFailureForbiddenCapability.GENERATES_RANDOMNESS,
    RecoveryFailureForbiddenCapability.RETRIES_TICKET_ID_CREATION,
    RecoveryFailureForbiddenCapability.DECODES_CREDENTIAL,
    RecoveryFailureForbiddenCapability.CALLS_VERIFIER_SERVICE,
    RecoveryFailureForbiddenCapability.COMPARES_HMAC_TAG,
    RecoveryFailureForbiddenCapability.READS_RESPONSE_STATE,
    RecoveryFailureForbiddenCapability.CALLS_KEY_SERVICE,
    RecoveryFailureForbiddenCapability.MUTATES_FIRST_READ,
    RecoveryFailureForbiddenCapability.LOGS_CREDENTIAL,
    RecoveryFailureForbiddenCapability.EXPOSES_ENDPOINT,
    RecoveryFailureForbiddenCapability.AUTHORIZES_RECOVERY,
)


@dataclass(frozen=True, slots=True)
class RecoveryFailureCaseV1:
    boundary: RecoveryFailureBoundary
    required_result: RecoveryFailureRequiredResult
    generic_external_result: bool
    fail_closed: bool


@dataclass(frozen=True, slots=True)
class RecoveryFailureProfileV1:
    scheme_version: int
    cases: tuple[RecoveryFailureCaseV1, ...]
    forbidden_capabilities: tuple[RecoveryFailureForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryFailureProfileV1:
    profile: RecoveryFailureProfileV1

    @property
    def generates_randomness(self) -> bool:
        return False

    @property
    def decodes_credential(self) -> bool:
        return False

    @property
    def calls_verifier_service(self) -> bool:
        return False

    @property
    def compares_hmac_tag(self) -> bool:
        return False

    @property
    def reads_response_state(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def mutates_first_read(self) -> bool:
        return False

    @property
    def logs_credential(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryFailureDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_true(value: object) -> bool:
    if value is not True:
        _reject()
    return True


def _require_boundary(value: object) -> RecoveryFailureBoundary:
    if isinstance(value, RecoveryFailureBoundary):
        return value
    _reject()


def _require_required_result(value: object) -> RecoveryFailureRequiredResult:
    if isinstance(value, RecoveryFailureRequiredResult):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> RecoveryFailureForbiddenCapability:
    if isinstance(value, RecoveryFailureForbiddenCapability):
        return value
    _reject()


def _expected_case_by_boundary(
    boundary: RecoveryFailureBoundary,
) -> RecoveryFailureCaseV1:
    try:
        index = RECOVERY_FAILURE_BOUNDARIES_V1.index(boundary)
    except ValueError:
        _reject()
    return RECOVERY_FAILURE_CASES_V1[index]


def _require_failure_case(value: object) -> RecoveryFailureCaseV1:
    if type(value) is not RecoveryFailureCaseV1:
        _reject()
    normalized = RecoveryFailureCaseV1(
        boundary=_require_boundary(value.boundary),
        required_result=_require_required_result(value.required_result),
        generic_external_result=_require_true(value.generic_external_result),
        fail_closed=_require_true(value.fail_closed),
    )
    if normalized != _expected_case_by_boundary(normalized.boundary):
        _reject()
    return normalized


def _require_failure_cases(
    value: object,
) -> tuple[RecoveryFailureCaseV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_failure_case(item) for item in value)
    if normalized != RECOVERY_FAILURE_CASES_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[RecoveryFailureForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != RECOVERY_FAILURE_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


RECOVERY_FAILURE_CASES_V1 = tuple(
    RecoveryFailureCaseV1(
        boundary=boundary,
        required_result=required_result,
        generic_external_result=True,
        fail_closed=True,
    )
    for boundary, required_result in zip(
        RECOVERY_FAILURE_BOUNDARIES_V1,
        RECOVERY_FAILURE_REQUIRED_RESULTS_V1,
        strict=True,
    )
)


def validate_recovery_failure_case_v1(
    failure_case: RecoveryFailureCaseV1,
) -> RecoveryFailureCaseV1:
    return _require_failure_case(failure_case)


def validate_recovery_failure_profile_v1(
    profile: RecoveryFailureProfileV1,
) -> StructurallyValidRecoveryFailureProfileV1:
    if type(profile) is not RecoveryFailureProfileV1:
        _reject()
    normalized = RecoveryFailureProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_FAILURE_PROFILE_VERSION,
        ),
        cases=_require_failure_cases(profile.cases),
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        ),
    )
    expected = expected_recovery_failure_profile_v1()
    if normalized != expected:
        _reject()
    return StructurallyValidRecoveryFailureProfileV1(normalized)


def expected_recovery_failure_profile_v1() -> RecoveryFailureProfileV1:
    return RecoveryFailureProfileV1(
        scheme_version=RECOVERY_FAILURE_PROFILE_VERSION,
        cases=RECOVERY_FAILURE_CASES_V1,
        forbidden_capabilities=RECOVERY_FAILURE_FORBIDDEN_CAPABILITIES_V1,
    )
