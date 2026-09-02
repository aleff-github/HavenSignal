"""Inert Recovery Verifier verification semantics descriptors from docs/21.

This module validates only static verification-semantics metadata for the
approved recovery credential construction. It does not compute HMACs, compare
tags, execute dummy verification, read response state, validate CAPTCHA, call a
Key Service, expose endpoints, log credentials, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryVerificationDescriptorRejected


RECOVERY_VERIFICATION_PROFILE_VERSION = 1
RECOVERY_VERIFICATION_TAG_BYTES = 32


class RecoveryVerificationAlgorithm(StrEnum):
    HMAC_SHA256_FULL_LENGTH = "HMAC_SHA256_FULL_LENGTH"


class RecoveryVerificationComparison(StrEnum):
    CONSTANT_TIME_FULL_TAG = "CONSTANT_TIME_FULL_TAG"


class RecoveryVerificationResultRule(StrEnum):
    BOOLEAN_ONLY = "BOOLEAN_ONLY"
    HMAC_SUCCESS_NECESSARY_NOT_SUFFICIENT = (
        "HMAC_SUCCESS_NECESSARY_NOT_SUFFICIENT"
    )


class RecoveryVerificationInputRequirement(StrEnum):
    CANONICAL_TICKET_ID = "CANONICAL_TICKET_ID"
    CANONICAL_RECOVERY_SECRET = "CANONICAL_RECOVERY_SECRET"
    STORED_SCHEME_VERSION = "STORED_SCHEME_VERSION"
    SERVER_SELECTED_KEY_ID = "SERVER_SELECTED_KEY_ID"
    STORED_FULL_LENGTH_TAG = "STORED_FULL_LENGTH_TAG"
    DUMMY_RECORD_FOR_UNKNOWN_TICKET = "DUMMY_RECORD_FOR_UNKNOWN_TICKET"


class RecoveryVerificationUniformityRequirement(StrEnum):
    GENERIC_EXTERNAL_NON_SUCCESS = "GENERIC_EXTERNAL_NON_SUCCESS"
    UNKNOWN_TICKET_DUMMY_VERIFICATION = "UNKNOWN_TICKET_DUMMY_VERIFICATION"
    SAME_STATUS_TEMPLATE_HEADERS_RESPONSE_CLASS_AND_WORDING = (
        "SAME_STATUS_TEMPLATE_HEADERS_RESPONSE_CLASS_AND_WORDING"
    )
    TIMING_DISTRIBUTION_TEST_REQUIRED = "TIMING_DISTRIBUTION_TEST_REQUIRED"
    NO_PERFECT_INDISTINGUISHABILITY_CLAIM = (
        "NO_PERFECT_INDISTINGUISHABILITY_CLAIM"
    )


class RecoveryVerificationForbiddenCapability(StrEnum):
    COMPUTES_HMAC = "COMPUTES_HMAC"
    COMPARES_TAGS = "COMPARES_TAGS"
    EXECUTES_DUMMY_VERIFICATION = "EXECUTES_DUMMY_VERIFICATION"
    RETURNS_EXPECTED_TAG = "RETURNS_EXPECTED_TAG"
    RETURNS_PARTIAL_MATCH_DETAIL = "RETURNS_PARTIAL_MATCH_DETAIL"
    READS_RESPONSE_STATE = "READS_RESPONSE_STATE"
    VALIDATES_CAPTCHA = "VALIDATES_CAPTCHA"
    CALLS_KEY_SERVICE = "CALLS_KEY_SERVICE"
    AUTHORIZES_RESPONSE_DEK_USE = "AUTHORIZES_RESPONSE_DEK_USE"
    LOGS_CREDENTIAL = "LOGS_CREDENTIAL"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_RECOVERY = "AUTHORIZES_RECOVERY"


RECOVERY_VERIFICATION_ALGORITHMS_V1 = (
    RecoveryVerificationAlgorithm.HMAC_SHA256_FULL_LENGTH,
)

RECOVERY_VERIFICATION_COMPARISONS_V1 = (
    RecoveryVerificationComparison.CONSTANT_TIME_FULL_TAG,
)

RECOVERY_VERIFICATION_RESULT_RULES_V1 = (
    RecoveryVerificationResultRule.BOOLEAN_ONLY,
    RecoveryVerificationResultRule.HMAC_SUCCESS_NECESSARY_NOT_SUFFICIENT,
)

RECOVERY_VERIFICATION_INPUT_REQUIREMENTS_V1 = (
    RecoveryVerificationInputRequirement.CANONICAL_TICKET_ID,
    RecoveryVerificationInputRequirement.CANONICAL_RECOVERY_SECRET,
    RecoveryVerificationInputRequirement.STORED_SCHEME_VERSION,
    RecoveryVerificationInputRequirement.SERVER_SELECTED_KEY_ID,
    RecoveryVerificationInputRequirement.STORED_FULL_LENGTH_TAG,
    RecoveryVerificationInputRequirement.DUMMY_RECORD_FOR_UNKNOWN_TICKET,
)

RECOVERY_VERIFICATION_UNIFORMITY_REQUIREMENTS_V1 = (
    RecoveryVerificationUniformityRequirement.GENERIC_EXTERNAL_NON_SUCCESS,
    RecoveryVerificationUniformityRequirement.UNKNOWN_TICKET_DUMMY_VERIFICATION,
    (
        RecoveryVerificationUniformityRequirement.
        SAME_STATUS_TEMPLATE_HEADERS_RESPONSE_CLASS_AND_WORDING
    ),
    RecoveryVerificationUniformityRequirement.TIMING_DISTRIBUTION_TEST_REQUIRED,
    RecoveryVerificationUniformityRequirement.NO_PERFECT_INDISTINGUISHABILITY_CLAIM,
)

RECOVERY_VERIFICATION_FORBIDDEN_CAPABILITIES_V1 = (
    RecoveryVerificationForbiddenCapability.COMPUTES_HMAC,
    RecoveryVerificationForbiddenCapability.COMPARES_TAGS,
    RecoveryVerificationForbiddenCapability.EXECUTES_DUMMY_VERIFICATION,
    RecoveryVerificationForbiddenCapability.RETURNS_EXPECTED_TAG,
    RecoveryVerificationForbiddenCapability.RETURNS_PARTIAL_MATCH_DETAIL,
    RecoveryVerificationForbiddenCapability.READS_RESPONSE_STATE,
    RecoveryVerificationForbiddenCapability.VALIDATES_CAPTCHA,
    RecoveryVerificationForbiddenCapability.CALLS_KEY_SERVICE,
    RecoveryVerificationForbiddenCapability.AUTHORIZES_RESPONSE_DEK_USE,
    RecoveryVerificationForbiddenCapability.LOGS_CREDENTIAL,
    RecoveryVerificationForbiddenCapability.EXPOSES_ENDPOINT,
    RecoveryVerificationForbiddenCapability.AUTHORIZES_RECOVERY,
)


@dataclass(frozen=True, slots=True)
class RecoveryVerificationAlgorithmProfileV1:
    algorithms: tuple[RecoveryVerificationAlgorithm, ...]
    tag_size_bytes: int
    comparisons: tuple[RecoveryVerificationComparison, ...]
    result_rules: tuple[RecoveryVerificationResultRule, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerificationInputProfileV1:
    requirements: tuple[RecoveryVerificationInputRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerificationUniformityProfileV1:
    requirements: tuple[RecoveryVerificationUniformityRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerificationCapabilityDenialProfileV1:
    forbidden_capabilities: tuple[RecoveryVerificationForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerificationProfileV1:
    scheme_version: int
    algorithm: RecoveryVerificationAlgorithmProfileV1
    inputs: RecoveryVerificationInputProfileV1
    uniformity: RecoveryVerificationUniformityProfileV1
    capability_denials: RecoveryVerificationCapabilityDenialProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryVerificationProfileV1:
    profile: RecoveryVerificationProfileV1

    @property
    def computes_hmac(self) -> bool:
        return False

    @property
    def compares_tags(self) -> bool:
        return False

    @property
    def executes_dummy_verification(self) -> bool:
        return False

    @property
    def returns_expected_tag(self) -> bool:
        return False

    @property
    def returns_partial_match_detail(self) -> bool:
        return False

    @property
    def reads_response_state(self) -> bool:
        return False

    @property
    def validates_captcha(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def authorizes_response_dek_use(self) -> bool:
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
    raise RecoveryVerificationDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_algorithm(value: object) -> RecoveryVerificationAlgorithm:
    if isinstance(value, RecoveryVerificationAlgorithm):
        return value
    _reject()


def _require_comparison(value: object) -> RecoveryVerificationComparison:
    if isinstance(value, RecoveryVerificationComparison):
        return value
    _reject()


def _require_result_rule(value: object) -> RecoveryVerificationResultRule:
    if isinstance(value, RecoveryVerificationResultRule):
        return value
    _reject()


def _require_input_requirement(
    value: object,
) -> RecoveryVerificationInputRequirement:
    if isinstance(value, RecoveryVerificationInputRequirement):
        return value
    _reject()


def _require_uniformity_requirement(
    value: object,
) -> RecoveryVerificationUniformityRequirement:
    if isinstance(value, RecoveryVerificationUniformityRequirement):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> RecoveryVerificationForbiddenCapability:
    if isinstance(value, RecoveryVerificationForbiddenCapability):
        return value
    _reject()


def _require_algorithms(
    value: object,
) -> tuple[RecoveryVerificationAlgorithm, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_algorithm(item) for item in value)
    if normalized != RECOVERY_VERIFICATION_ALGORITHMS_V1:
        _reject()
    return normalized


def _require_comparisons(
    value: object,
) -> tuple[RecoveryVerificationComparison, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_comparison(item) for item in value)
    if normalized != RECOVERY_VERIFICATION_COMPARISONS_V1:
        _reject()
    return normalized


def _require_result_rules(
    value: object,
) -> tuple[RecoveryVerificationResultRule, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_result_rule(item) for item in value)
    if normalized != RECOVERY_VERIFICATION_RESULT_RULES_V1:
        _reject()
    return normalized


def _require_input_requirements(
    value: object,
) -> tuple[RecoveryVerificationInputRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_input_requirement(item) for item in value)
    if normalized != RECOVERY_VERIFICATION_INPUT_REQUIREMENTS_V1:
        _reject()
    return normalized


def _require_uniformity_requirements(
    value: object,
) -> tuple[RecoveryVerificationUniformityRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_uniformity_requirement(item) for item in value)
    if normalized != RECOVERY_VERIFICATION_UNIFORMITY_REQUIREMENTS_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[RecoveryVerificationForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != RECOVERY_VERIFICATION_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


def validate_recovery_verification_algorithm_profile_v1(
    profile: RecoveryVerificationAlgorithmProfileV1,
) -> RecoveryVerificationAlgorithmProfileV1:
    if type(profile) is not RecoveryVerificationAlgorithmProfileV1:
        _reject()
    normalized = RecoveryVerificationAlgorithmProfileV1(
        algorithms=_require_algorithms(profile.algorithms),
        tag_size_bytes=_require_uint_exact(
            profile.tag_size_bytes,
            expected=RECOVERY_VERIFICATION_TAG_BYTES,
        ),
        comparisons=_require_comparisons(profile.comparisons),
        result_rules=_require_result_rules(profile.result_rules),
    )
    if normalized != expected_recovery_verification_algorithm_profile_v1():
        _reject()
    return normalized


def validate_recovery_verification_input_profile_v1(
    profile: RecoveryVerificationInputProfileV1,
) -> RecoveryVerificationInputProfileV1:
    if type(profile) is not RecoveryVerificationInputProfileV1:
        _reject()
    normalized = RecoveryVerificationInputProfileV1(
        requirements=_require_input_requirements(profile.requirements)
    )
    if normalized != expected_recovery_verification_input_profile_v1():
        _reject()
    return normalized


def validate_recovery_verification_uniformity_profile_v1(
    profile: RecoveryVerificationUniformityProfileV1,
) -> RecoveryVerificationUniformityProfileV1:
    if type(profile) is not RecoveryVerificationUniformityProfileV1:
        _reject()
    normalized = RecoveryVerificationUniformityProfileV1(
        requirements=_require_uniformity_requirements(profile.requirements)
    )
    if normalized != expected_recovery_verification_uniformity_profile_v1():
        _reject()
    return normalized


def validate_recovery_verification_capability_denial_profile_v1(
    profile: RecoveryVerificationCapabilityDenialProfileV1,
) -> RecoveryVerificationCapabilityDenialProfileV1:
    if type(profile) is not RecoveryVerificationCapabilityDenialProfileV1:
        _reject()
    normalized = RecoveryVerificationCapabilityDenialProfileV1(
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        )
    )
    if normalized != expected_recovery_verification_capability_denial_profile_v1():
        _reject()
    return normalized


def validate_recovery_verification_profile_v1(
    profile: RecoveryVerificationProfileV1,
) -> StructurallyValidRecoveryVerificationProfileV1:
    if type(profile) is not RecoveryVerificationProfileV1:
        _reject()
    normalized = RecoveryVerificationProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_VERIFICATION_PROFILE_VERSION,
        ),
        algorithm=validate_recovery_verification_algorithm_profile_v1(
            profile.algorithm
        ),
        inputs=validate_recovery_verification_input_profile_v1(profile.inputs),
        uniformity=validate_recovery_verification_uniformity_profile_v1(
            profile.uniformity
        ),
        capability_denials=(
            validate_recovery_verification_capability_denial_profile_v1(
                profile.capability_denials
            )
        ),
    )
    if normalized != expected_recovery_verification_profile_v1():
        _reject()
    return StructurallyValidRecoveryVerificationProfileV1(normalized)


def expected_recovery_verification_algorithm_profile_v1(
) -> RecoveryVerificationAlgorithmProfileV1:
    return RecoveryVerificationAlgorithmProfileV1(
        algorithms=RECOVERY_VERIFICATION_ALGORITHMS_V1,
        tag_size_bytes=RECOVERY_VERIFICATION_TAG_BYTES,
        comparisons=RECOVERY_VERIFICATION_COMPARISONS_V1,
        result_rules=RECOVERY_VERIFICATION_RESULT_RULES_V1,
    )


def expected_recovery_verification_input_profile_v1(
) -> RecoveryVerificationInputProfileV1:
    return RecoveryVerificationInputProfileV1(
        requirements=RECOVERY_VERIFICATION_INPUT_REQUIREMENTS_V1
    )


def expected_recovery_verification_uniformity_profile_v1(
) -> RecoveryVerificationUniformityProfileV1:
    return RecoveryVerificationUniformityProfileV1(
        requirements=RECOVERY_VERIFICATION_UNIFORMITY_REQUIREMENTS_V1
    )


def expected_recovery_verification_capability_denial_profile_v1(
) -> RecoveryVerificationCapabilityDenialProfileV1:
    return RecoveryVerificationCapabilityDenialProfileV1(
        forbidden_capabilities=RECOVERY_VERIFICATION_FORBIDDEN_CAPABILITIES_V1
    )


def expected_recovery_verification_profile_v1(
) -> RecoveryVerificationProfileV1:
    return RecoveryVerificationProfileV1(
        scheme_version=RECOVERY_VERIFICATION_PROFILE_VERSION,
        algorithm=expected_recovery_verification_algorithm_profile_v1(),
        inputs=expected_recovery_verification_input_profile_v1(),
        uniformity=expected_recovery_verification_uniformity_profile_v1(),
        capability_denials=(
            expected_recovery_verification_capability_denial_profile_v1()
        ),
    )
