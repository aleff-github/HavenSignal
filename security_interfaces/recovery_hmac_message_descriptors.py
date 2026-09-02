"""Inert Recovery Verifier HMAC message layout descriptors from docs/21.

This module validates only static layout metadata for the canonical recovery
HMAC message. It does not accept credential values, concatenate bytes, compute
HMACs, retain messages, access keys, expose endpoints, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryHmacMessageDescriptorRejected


RECOVERY_HMAC_MESSAGE_PROFILE_VERSION = 1
RECOVERY_HMAC_DOMAIN_LABEL = "anonymous-reporting/recovery-verifier/v1"
RECOVERY_HMAC_SEPARATOR_BYTE = 0
RECOVERY_HMAC_TICKET_ID_BYTES = 16
RECOVERY_HMAC_RECOVERY_SECRET_BYTES = 32


class RecoveryHmacMessageComponent(StrEnum):
    DOMAIN_LABEL_ASCII = "DOMAIN_LABEL_ASCII"
    ZERO_SEPARATOR = "ZERO_SEPARATOR"
    TICKET_ID_BYTES = "TICKET_ID_BYTES"
    RECOVERY_SECRET_BYTES = "RECOVERY_SECRET_BYTES"


class RecoveryHmacMessageRequirement(StrEnum):
    FIXED_ORDER = "FIXED_ORDER"
    DOMAIN_SEPARATED = "DOMAIN_SEPARATED"
    VERSION_BOUND_DOMAIN_LABEL = "VERSION_BOUND_DOMAIN_LABEL"
    TERMINATING_ZERO_SEPARATOR = "TERMINATING_ZERO_SEPARATOR"
    FIXED_FIELD_LENGTHS = "FIXED_FIELD_LENGTHS"
    UNAMBIGUOUS_AND_PURPOSE_SPECIFIC = "UNAMBIGUOUS_AND_PURPOSE_SPECIFIC"


class RecoveryHmacMessageForbiddenCapability(StrEnum):
    ACCEPTS_CREDENTIAL_VALUES = "ACCEPTS_CREDENTIAL_VALUES"
    CONCATENATES_BYTES = "CONCATENATES_BYTES"
    COMPUTES_HMAC = "COMPUTES_HMAC"
    STORES_CANONICAL_MESSAGE = "STORES_CANONICAL_MESSAGE"
    STORES_RECOVERY_SECRET = "STORES_RECOVERY_SECRET"
    ACCESSES_VERIFIER_KEY = "ACCESSES_VERIFIER_KEY"
    RETURNS_VERIFIER_TAG = "RETURNS_VERIFIER_TAG"
    LOGS_MESSAGE_OR_CREDENTIAL = "LOGS_MESSAGE_OR_CREDENTIAL"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_RECOVERY = "AUTHORIZES_RECOVERY"


RECOVERY_HMAC_MESSAGE_COMPONENTS_V1 = (
    RecoveryHmacMessageComponent.DOMAIN_LABEL_ASCII,
    RecoveryHmacMessageComponent.ZERO_SEPARATOR,
    RecoveryHmacMessageComponent.TICKET_ID_BYTES,
    RecoveryHmacMessageComponent.RECOVERY_SECRET_BYTES,
)

RECOVERY_HMAC_MESSAGE_REQUIREMENTS_V1 = (
    RecoveryHmacMessageRequirement.FIXED_ORDER,
    RecoveryHmacMessageRequirement.DOMAIN_SEPARATED,
    RecoveryHmacMessageRequirement.VERSION_BOUND_DOMAIN_LABEL,
    RecoveryHmacMessageRequirement.TERMINATING_ZERO_SEPARATOR,
    RecoveryHmacMessageRequirement.FIXED_FIELD_LENGTHS,
    RecoveryHmacMessageRequirement.UNAMBIGUOUS_AND_PURPOSE_SPECIFIC,
)

RECOVERY_HMAC_MESSAGE_FORBIDDEN_CAPABILITIES_V1 = (
    RecoveryHmacMessageForbiddenCapability.ACCEPTS_CREDENTIAL_VALUES,
    RecoveryHmacMessageForbiddenCapability.CONCATENATES_BYTES,
    RecoveryHmacMessageForbiddenCapability.COMPUTES_HMAC,
    RecoveryHmacMessageForbiddenCapability.STORES_CANONICAL_MESSAGE,
    RecoveryHmacMessageForbiddenCapability.STORES_RECOVERY_SECRET,
    RecoveryHmacMessageForbiddenCapability.ACCESSES_VERIFIER_KEY,
    RecoveryHmacMessageForbiddenCapability.RETURNS_VERIFIER_TAG,
    RecoveryHmacMessageForbiddenCapability.LOGS_MESSAGE_OR_CREDENTIAL,
    RecoveryHmacMessageForbiddenCapability.EXPOSES_ENDPOINT,
    RecoveryHmacMessageForbiddenCapability.AUTHORIZES_RECOVERY,
)


@dataclass(frozen=True, slots=True)
class RecoveryHmacMessageLayoutProfileV1:
    components: tuple[RecoveryHmacMessageComponent, ...]
    domain_label: str
    separator_byte: int
    ticket_id_size_bytes: int
    recovery_secret_size_bytes: int


@dataclass(frozen=True, slots=True)
class RecoveryHmacMessageRequirementProfileV1:
    requirements: tuple[RecoveryHmacMessageRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryHmacMessageCapabilityDenialProfileV1:
    forbidden_capabilities: tuple[RecoveryHmacMessageForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class RecoveryHmacMessageProfileV1:
    scheme_version: int
    layout: RecoveryHmacMessageLayoutProfileV1
    requirements: RecoveryHmacMessageRequirementProfileV1
    capability_denials: RecoveryHmacMessageCapabilityDenialProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryHmacMessageProfileV1:
    profile: RecoveryHmacMessageProfileV1

    @property
    def accepts_credential_values(self) -> bool:
        return False

    @property
    def concatenates_bytes(self) -> bool:
        return False

    @property
    def computes_hmac(self) -> bool:
        return False

    @property
    def stores_canonical_message(self) -> bool:
        return False

    @property
    def stores_recovery_secret(self) -> bool:
        return False

    @property
    def accesses_verifier_key(self) -> bool:
        return False

    @property
    def returns_verifier_tag(self) -> bool:
        return False

    @property
    def logs_message_or_credential(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryHmacMessageDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_string_exact(value: object, *, expected: str) -> str:
    if type(value) is not str or value != expected:
        _reject()
    return value


def _require_component(value: object) -> RecoveryHmacMessageComponent:
    if isinstance(value, RecoveryHmacMessageComponent):
        return value
    _reject()


def _require_requirement(value: object) -> RecoveryHmacMessageRequirement:
    if isinstance(value, RecoveryHmacMessageRequirement):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> RecoveryHmacMessageForbiddenCapability:
    if isinstance(value, RecoveryHmacMessageForbiddenCapability):
        return value
    _reject()


def _require_components(
    value: object,
) -> tuple[RecoveryHmacMessageComponent, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_component(item) for item in value)
    if normalized != RECOVERY_HMAC_MESSAGE_COMPONENTS_V1:
        _reject()
    return normalized


def _require_requirements(
    value: object,
) -> tuple[RecoveryHmacMessageRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_requirement(item) for item in value)
    if normalized != RECOVERY_HMAC_MESSAGE_REQUIREMENTS_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[RecoveryHmacMessageForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != RECOVERY_HMAC_MESSAGE_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


def validate_recovery_hmac_message_layout_profile_v1(
    profile: RecoveryHmacMessageLayoutProfileV1,
) -> RecoveryHmacMessageLayoutProfileV1:
    if type(profile) is not RecoveryHmacMessageLayoutProfileV1:
        _reject()
    normalized = RecoveryHmacMessageLayoutProfileV1(
        components=_require_components(profile.components),
        domain_label=_require_string_exact(
            profile.domain_label,
            expected=RECOVERY_HMAC_DOMAIN_LABEL,
        ),
        separator_byte=_require_uint_exact(
            profile.separator_byte,
            expected=RECOVERY_HMAC_SEPARATOR_BYTE,
        ),
        ticket_id_size_bytes=_require_uint_exact(
            profile.ticket_id_size_bytes,
            expected=RECOVERY_HMAC_TICKET_ID_BYTES,
        ),
        recovery_secret_size_bytes=_require_uint_exact(
            profile.recovery_secret_size_bytes,
            expected=RECOVERY_HMAC_RECOVERY_SECRET_BYTES,
        ),
    )
    if normalized != expected_recovery_hmac_message_layout_profile_v1():
        _reject()
    return normalized


def validate_recovery_hmac_message_requirement_profile_v1(
    profile: RecoveryHmacMessageRequirementProfileV1,
) -> RecoveryHmacMessageRequirementProfileV1:
    if type(profile) is not RecoveryHmacMessageRequirementProfileV1:
        _reject()
    normalized = RecoveryHmacMessageRequirementProfileV1(
        requirements=_require_requirements(profile.requirements)
    )
    if normalized != expected_recovery_hmac_message_requirement_profile_v1():
        _reject()
    return normalized


def validate_recovery_hmac_message_capability_denial_profile_v1(
    profile: RecoveryHmacMessageCapabilityDenialProfileV1,
) -> RecoveryHmacMessageCapabilityDenialProfileV1:
    if type(profile) is not RecoveryHmacMessageCapabilityDenialProfileV1:
        _reject()
    normalized = RecoveryHmacMessageCapabilityDenialProfileV1(
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        )
    )
    if normalized != expected_recovery_hmac_message_capability_denial_profile_v1():
        _reject()
    return normalized


def validate_recovery_hmac_message_profile_v1(
    profile: RecoveryHmacMessageProfileV1,
) -> StructurallyValidRecoveryHmacMessageProfileV1:
    if type(profile) is not RecoveryHmacMessageProfileV1:
        _reject()
    normalized = RecoveryHmacMessageProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_HMAC_MESSAGE_PROFILE_VERSION,
        ),
        layout=validate_recovery_hmac_message_layout_profile_v1(
            profile.layout
        ),
        requirements=validate_recovery_hmac_message_requirement_profile_v1(
            profile.requirements
        ),
        capability_denials=(
            validate_recovery_hmac_message_capability_denial_profile_v1(
                profile.capability_denials
            )
        ),
    )
    if normalized != expected_recovery_hmac_message_profile_v1():
        _reject()
    return StructurallyValidRecoveryHmacMessageProfileV1(normalized)


def expected_recovery_hmac_message_layout_profile_v1(
) -> RecoveryHmacMessageLayoutProfileV1:
    return RecoveryHmacMessageLayoutProfileV1(
        components=RECOVERY_HMAC_MESSAGE_COMPONENTS_V1,
        domain_label=RECOVERY_HMAC_DOMAIN_LABEL,
        separator_byte=RECOVERY_HMAC_SEPARATOR_BYTE,
        ticket_id_size_bytes=RECOVERY_HMAC_TICKET_ID_BYTES,
        recovery_secret_size_bytes=RECOVERY_HMAC_RECOVERY_SECRET_BYTES,
    )


def expected_recovery_hmac_message_requirement_profile_v1(
) -> RecoveryHmacMessageRequirementProfileV1:
    return RecoveryHmacMessageRequirementProfileV1(
        requirements=RECOVERY_HMAC_MESSAGE_REQUIREMENTS_V1
    )


def expected_recovery_hmac_message_capability_denial_profile_v1(
) -> RecoveryHmacMessageCapabilityDenialProfileV1:
    return RecoveryHmacMessageCapabilityDenialProfileV1(
        forbidden_capabilities=RECOVERY_HMAC_MESSAGE_FORBIDDEN_CAPABILITIES_V1
    )


def expected_recovery_hmac_message_profile_v1(
) -> RecoveryHmacMessageProfileV1:
    return RecoveryHmacMessageProfileV1(
        scheme_version=RECOVERY_HMAC_MESSAGE_PROFILE_VERSION,
        layout=expected_recovery_hmac_message_layout_profile_v1(),
        requirements=expected_recovery_hmac_message_requirement_profile_v1(),
        capability_denials=(
            expected_recovery_hmac_message_capability_denial_profile_v1()
        ),
    )
