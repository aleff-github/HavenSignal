"""Inert Recovery Verifier Service operation descriptors from docs/21.

This module validates only static service-operation metadata for the approved
Recovery Verifier Service boundary. It does not implement service calls,
generate credentials, compute HMACs, compare tags, persist verifier records,
perform lookups, expose endpoints, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryVerifierServiceDescriptorRejected


RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION = 1


class RecoveryVerifierServiceOperation(StrEnum):
    CREATE_ONLY_FOR_NEW_SUBMISSION_ATTEMPT = (
        "CREATE_ONLY_FOR_NEW_SUBMISSION_ATTEMPT"
    )
    BOOLEAN_VERIFY_FOR_RECOVERY = "BOOLEAN_VERIFY_FOR_RECOVERY"


class RecoveryVerifierServiceChannelRequirement(StrEnum):
    AUTHENTICATED = "AUTHENTICATED"
    ENCRYPTED = "ENCRYPTED"
    BOUNDED = "BOUNDED"
    BODY_EXCLUDED_FROM_PROXY_LOGS = "BODY_EXCLUDED_FROM_PROXY_LOGS"
    CREDENTIAL_FIELDS_EXCLUDED_FROM_APPLICATION_LOGS = (
        "CREDENTIAL_FIELDS_EXCLUDED_FROM_APPLICATION_LOGS"
    )
    CREDENTIAL_FIELDS_EXCLUDED_FROM_AUDIT_TRACING_AND_ERROR_LOGS = (
        "CREDENTIAL_FIELDS_EXCLUDED_FROM_AUDIT_TRACING_AND_ERROR_LOGS"
    )


class RecoveryVerifierServiceCreateRule(StrEnum):
    REPORTER_GATEWAY_TRANSIENT_INPUT_ONLY = (
        "REPORTER_GATEWAY_TRANSIENT_INPUT_ONLY"
    )
    BOUND_TO_ONE_CURRENT_UNACCEPTED_SUBMISSION_ATTEMPT = (
        "BOUND_TO_ONE_CURRENT_UNACCEPTED_SUBMISSION_ATTEMPT"
    )
    CANNOT_PRODUCE_OR_REPLACE_EXISTING_TICKET_VERIFIER = (
        "CANNOT_PRODUCE_OR_REPLACE_EXISTING_TICKET_VERIFIER"
    )
    RETURNS_ONLY_VERSION_KEY_ID_AND_VERIFIER_TAG = (
        "RETURNS_ONLY_VERSION_KEY_ID_AND_VERIFIER_TAG"
    )


class RecoveryVerifierServiceVerifyRule(StrEnum):
    RECOVERY_GATEWAY_POST_INPUT_ONLY = "RECOVERY_GATEWAY_POST_INPUT_ONLY"
    RETURNS_BOOLEAN_AUTHORIZATION_RESULT_ONLY = (
        "RETURNS_BOOLEAN_AUTHORIZATION_RESULT_ONLY"
    )
    NEVER_RETURNS_EXPECTED_TAG = "NEVER_RETURNS_EXPECTED_TAG"
    NEVER_RETURNS_PARTIAL_MATCH_INFORMATION = (
        "NEVER_RETURNS_PARTIAL_MATCH_INFORMATION"
    )
    VERIFIER_SUCCESS_IS_NOT_RESPONSE_DEK_AUTHORIZATION = (
        "VERIFIER_SUCCESS_IS_NOT_RESPONSE_DEK_AUTHORIZATION"
    )


class RecoveryVerifierServiceForbiddenCapability(StrEnum):
    IMPLEMENTS_SERVICE_CALL = "IMPLEMENTS_SERVICE_CALL"
    GENERATES_CREDENTIALS = "GENERATES_CREDENTIALS"
    COMPUTES_HMAC = "COMPUTES_HMAC"
    COMPARES_TAGS = "COMPARES_TAGS"
    PERSISTS_VERIFIER_RECORD = "PERSISTS_VERIFIER_RECORD"
    PERFORMS_LOOKUP = "PERFORMS_LOOKUP"
    ACCEPTS_REPORTER_SUPPLIED_KEY_ID = "ACCEPTS_REPORTER_SUPPLIED_KEY_ID"
    RETURNS_RAW_VERIFIER_KEY = "RETURNS_RAW_VERIFIER_KEY"
    RETURNS_EXPECTED_TAG = "RETURNS_EXPECTED_TAG"
    RETURNS_PARTIAL_MATCH_DETAIL = "RETURNS_PARTIAL_MATCH_DETAIL"
    READS_RESPONSE_STATE = "READS_RESPONSE_STATE"
    CALLS_KEY_SERVICE = "CALLS_KEY_SERVICE"
    AUTHORIZES_RESPONSE_DEK_USE = "AUTHORIZES_RESPONSE_DEK_USE"
    LOGS_CREDENTIALS = "LOGS_CREDENTIALS"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_RECOVERY = "AUTHORIZES_RECOVERY"


RECOVERY_VERIFIER_SERVICE_OPERATIONS_V1 = (
    RecoveryVerifierServiceOperation.CREATE_ONLY_FOR_NEW_SUBMISSION_ATTEMPT,
    RecoveryVerifierServiceOperation.BOOLEAN_VERIFY_FOR_RECOVERY,
)

RECOVERY_VERIFIER_SERVICE_CHANNEL_REQUIREMENTS_V1 = (
    RecoveryVerifierServiceChannelRequirement.AUTHENTICATED,
    RecoveryVerifierServiceChannelRequirement.ENCRYPTED,
    RecoveryVerifierServiceChannelRequirement.BOUNDED,
    RecoveryVerifierServiceChannelRequirement.BODY_EXCLUDED_FROM_PROXY_LOGS,
    (
        RecoveryVerifierServiceChannelRequirement.
        CREDENTIAL_FIELDS_EXCLUDED_FROM_APPLICATION_LOGS
    ),
    (
        RecoveryVerifierServiceChannelRequirement.
        CREDENTIAL_FIELDS_EXCLUDED_FROM_AUDIT_TRACING_AND_ERROR_LOGS
    ),
)

RECOVERY_VERIFIER_SERVICE_CREATE_RULES_V1 = (
    RecoveryVerifierServiceCreateRule.REPORTER_GATEWAY_TRANSIENT_INPUT_ONLY,
    (
        RecoveryVerifierServiceCreateRule.
        BOUND_TO_ONE_CURRENT_UNACCEPTED_SUBMISSION_ATTEMPT
    ),
    (
        RecoveryVerifierServiceCreateRule.
        CANNOT_PRODUCE_OR_REPLACE_EXISTING_TICKET_VERIFIER
    ),
    RecoveryVerifierServiceCreateRule.RETURNS_ONLY_VERSION_KEY_ID_AND_VERIFIER_TAG,
)

RECOVERY_VERIFIER_SERVICE_VERIFY_RULES_V1 = (
    RecoveryVerifierServiceVerifyRule.RECOVERY_GATEWAY_POST_INPUT_ONLY,
    RecoveryVerifierServiceVerifyRule.RETURNS_BOOLEAN_AUTHORIZATION_RESULT_ONLY,
    RecoveryVerifierServiceVerifyRule.NEVER_RETURNS_EXPECTED_TAG,
    RecoveryVerifierServiceVerifyRule.NEVER_RETURNS_PARTIAL_MATCH_INFORMATION,
    (
        RecoveryVerifierServiceVerifyRule.
        VERIFIER_SUCCESS_IS_NOT_RESPONSE_DEK_AUTHORIZATION
    ),
)

RECOVERY_VERIFIER_SERVICE_FORBIDDEN_CAPABILITIES_V1 = (
    RecoveryVerifierServiceForbiddenCapability.IMPLEMENTS_SERVICE_CALL,
    RecoveryVerifierServiceForbiddenCapability.GENERATES_CREDENTIALS,
    RecoveryVerifierServiceForbiddenCapability.COMPUTES_HMAC,
    RecoveryVerifierServiceForbiddenCapability.COMPARES_TAGS,
    RecoveryVerifierServiceForbiddenCapability.PERSISTS_VERIFIER_RECORD,
    RecoveryVerifierServiceForbiddenCapability.PERFORMS_LOOKUP,
    RecoveryVerifierServiceForbiddenCapability.ACCEPTS_REPORTER_SUPPLIED_KEY_ID,
    RecoveryVerifierServiceForbiddenCapability.RETURNS_RAW_VERIFIER_KEY,
    RecoveryVerifierServiceForbiddenCapability.RETURNS_EXPECTED_TAG,
    RecoveryVerifierServiceForbiddenCapability.RETURNS_PARTIAL_MATCH_DETAIL,
    RecoveryVerifierServiceForbiddenCapability.READS_RESPONSE_STATE,
    RecoveryVerifierServiceForbiddenCapability.CALLS_KEY_SERVICE,
    RecoveryVerifierServiceForbiddenCapability.AUTHORIZES_RESPONSE_DEK_USE,
    RecoveryVerifierServiceForbiddenCapability.LOGS_CREDENTIALS,
    RecoveryVerifierServiceForbiddenCapability.EXPOSES_ENDPOINT,
    RecoveryVerifierServiceForbiddenCapability.AUTHORIZES_RECOVERY,
)


@dataclass(frozen=True, slots=True)
class RecoveryVerifierServiceOperationProfileV1:
    operations: tuple[RecoveryVerifierServiceOperation, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierServiceChannelProfileV1:
    requirements: tuple[RecoveryVerifierServiceChannelRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierServiceCreateProfileV1:
    rules: tuple[RecoveryVerifierServiceCreateRule, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierServiceVerifyProfileV1:
    rules: tuple[RecoveryVerifierServiceVerifyRule, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierServiceCapabilityDenialProfileV1:
    forbidden_capabilities: tuple[RecoveryVerifierServiceForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierServiceProfileV1:
    scheme_version: int
    operations: RecoveryVerifierServiceOperationProfileV1
    channel: RecoveryVerifierServiceChannelProfileV1
    create: RecoveryVerifierServiceCreateProfileV1
    verify: RecoveryVerifierServiceVerifyProfileV1
    capability_denials: RecoveryVerifierServiceCapabilityDenialProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryVerifierServiceProfileV1:
    profile: RecoveryVerifierServiceProfileV1

    @property
    def implements_service_call(self) -> bool:
        return False

    @property
    def generates_credentials(self) -> bool:
        return False

    @property
    def computes_hmac(self) -> bool:
        return False

    @property
    def compares_tags(self) -> bool:
        return False

    @property
    def persists_verifier_record(self) -> bool:
        return False

    @property
    def performs_lookup(self) -> bool:
        return False

    @property
    def returns_raw_verifier_key(self) -> bool:
        return False

    @property
    def returns_expected_tag(self) -> bool:
        return False

    @property
    def returns_partial_match_detail(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def authorizes_response_dek_use(self) -> bool:
        return False

    @property
    def logs_credentials(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryVerifierServiceDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_operation(value: object) -> RecoveryVerifierServiceOperation:
    if isinstance(value, RecoveryVerifierServiceOperation):
        return value
    _reject()


def _require_channel_requirement(
    value: object,
) -> RecoveryVerifierServiceChannelRequirement:
    if isinstance(value, RecoveryVerifierServiceChannelRequirement):
        return value
    _reject()


def _require_create_rule(value: object) -> RecoveryVerifierServiceCreateRule:
    if isinstance(value, RecoveryVerifierServiceCreateRule):
        return value
    _reject()


def _require_verify_rule(value: object) -> RecoveryVerifierServiceVerifyRule:
    if isinstance(value, RecoveryVerifierServiceVerifyRule):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> RecoveryVerifierServiceForbiddenCapability:
    if isinstance(value, RecoveryVerifierServiceForbiddenCapability):
        return value
    _reject()


def _require_operations(
    value: object,
) -> tuple[RecoveryVerifierServiceOperation, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_operation(item) for item in value)
    if normalized != RECOVERY_VERIFIER_SERVICE_OPERATIONS_V1:
        _reject()
    return normalized


def _require_channel_requirements(
    value: object,
) -> tuple[RecoveryVerifierServiceChannelRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_channel_requirement(item) for item in value)
    if normalized != RECOVERY_VERIFIER_SERVICE_CHANNEL_REQUIREMENTS_V1:
        _reject()
    return normalized


def _require_create_rules(
    value: object,
) -> tuple[RecoveryVerifierServiceCreateRule, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_create_rule(item) for item in value)
    if normalized != RECOVERY_VERIFIER_SERVICE_CREATE_RULES_V1:
        _reject()
    return normalized


def _require_verify_rules(
    value: object,
) -> tuple[RecoveryVerifierServiceVerifyRule, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_verify_rule(item) for item in value)
    if normalized != RECOVERY_VERIFIER_SERVICE_VERIFY_RULES_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[RecoveryVerifierServiceForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != RECOVERY_VERIFIER_SERVICE_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


def validate_recovery_verifier_service_operation_profile_v1(
    profile: RecoveryVerifierServiceOperationProfileV1,
) -> RecoveryVerifierServiceOperationProfileV1:
    if type(profile) is not RecoveryVerifierServiceOperationProfileV1:
        _reject()
    normalized = RecoveryVerifierServiceOperationProfileV1(
        operations=_require_operations(profile.operations)
    )
    if normalized != expected_recovery_verifier_service_operation_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_service_channel_profile_v1(
    profile: RecoveryVerifierServiceChannelProfileV1,
) -> RecoveryVerifierServiceChannelProfileV1:
    if type(profile) is not RecoveryVerifierServiceChannelProfileV1:
        _reject()
    normalized = RecoveryVerifierServiceChannelProfileV1(
        requirements=_require_channel_requirements(profile.requirements)
    )
    if normalized != expected_recovery_verifier_service_channel_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_service_create_profile_v1(
    profile: RecoveryVerifierServiceCreateProfileV1,
) -> RecoveryVerifierServiceCreateProfileV1:
    if type(profile) is not RecoveryVerifierServiceCreateProfileV1:
        _reject()
    normalized = RecoveryVerifierServiceCreateProfileV1(
        rules=_require_create_rules(profile.rules)
    )
    if normalized != expected_recovery_verifier_service_create_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_service_verify_profile_v1(
    profile: RecoveryVerifierServiceVerifyProfileV1,
) -> RecoveryVerifierServiceVerifyProfileV1:
    if type(profile) is not RecoveryVerifierServiceVerifyProfileV1:
        _reject()
    normalized = RecoveryVerifierServiceVerifyProfileV1(
        rules=_require_verify_rules(profile.rules)
    )
    if normalized != expected_recovery_verifier_service_verify_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_service_capability_denial_profile_v1(
    profile: RecoveryVerifierServiceCapabilityDenialProfileV1,
) -> RecoveryVerifierServiceCapabilityDenialProfileV1:
    if type(profile) is not RecoveryVerifierServiceCapabilityDenialProfileV1:
        _reject()
    normalized = RecoveryVerifierServiceCapabilityDenialProfileV1(
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        )
    )
    if normalized != expected_recovery_verifier_service_capability_denial_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_service_profile_v1(
    profile: RecoveryVerifierServiceProfileV1,
) -> StructurallyValidRecoveryVerifierServiceProfileV1:
    if type(profile) is not RecoveryVerifierServiceProfileV1:
        _reject()
    normalized = RecoveryVerifierServiceProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION,
        ),
        operations=validate_recovery_verifier_service_operation_profile_v1(
            profile.operations
        ),
        channel=validate_recovery_verifier_service_channel_profile_v1(
            profile.channel
        ),
        create=validate_recovery_verifier_service_create_profile_v1(
            profile.create
        ),
        verify=validate_recovery_verifier_service_verify_profile_v1(
            profile.verify
        ),
        capability_denials=(
            validate_recovery_verifier_service_capability_denial_profile_v1(
                profile.capability_denials
            )
        ),
    )
    if normalized != expected_recovery_verifier_service_profile_v1():
        _reject()
    return StructurallyValidRecoveryVerifierServiceProfileV1(normalized)


def expected_recovery_verifier_service_operation_profile_v1(
) -> RecoveryVerifierServiceOperationProfileV1:
    return RecoveryVerifierServiceOperationProfileV1(
        operations=RECOVERY_VERIFIER_SERVICE_OPERATIONS_V1
    )


def expected_recovery_verifier_service_channel_profile_v1(
) -> RecoveryVerifierServiceChannelProfileV1:
    return RecoveryVerifierServiceChannelProfileV1(
        requirements=RECOVERY_VERIFIER_SERVICE_CHANNEL_REQUIREMENTS_V1
    )


def expected_recovery_verifier_service_create_profile_v1(
) -> RecoveryVerifierServiceCreateProfileV1:
    return RecoveryVerifierServiceCreateProfileV1(
        rules=RECOVERY_VERIFIER_SERVICE_CREATE_RULES_V1
    )


def expected_recovery_verifier_service_verify_profile_v1(
) -> RecoveryVerifierServiceVerifyProfileV1:
    return RecoveryVerifierServiceVerifyProfileV1(
        rules=RECOVERY_VERIFIER_SERVICE_VERIFY_RULES_V1
    )


def expected_recovery_verifier_service_capability_denial_profile_v1(
) -> RecoveryVerifierServiceCapabilityDenialProfileV1:
    return RecoveryVerifierServiceCapabilityDenialProfileV1(
        forbidden_capabilities=RECOVERY_VERIFIER_SERVICE_FORBIDDEN_CAPABILITIES_V1
    )


def expected_recovery_verifier_service_profile_v1(
) -> RecoveryVerifierServiceProfileV1:
    return RecoveryVerifierServiceProfileV1(
        scheme_version=RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION,
        operations=expected_recovery_verifier_service_operation_profile_v1(),
        channel=expected_recovery_verifier_service_channel_profile_v1(),
        create=expected_recovery_verifier_service_create_profile_v1(),
        verify=expected_recovery_verifier_service_verify_profile_v1(),
        capability_denials=(
            expected_recovery_verifier_service_capability_denial_profile_v1()
        ),
    )
