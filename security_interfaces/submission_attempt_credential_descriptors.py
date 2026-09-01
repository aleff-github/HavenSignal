"""Inert submission-attempt credential descriptors from the approved docs/20 flow.

This module validates only static attempt-credential policy metadata. It does
not generate credentials, verify credentials, persist credential material,
install cookies, inspect requests, claim attempts, call services, expose
endpoints, or authorize submission/report access.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SubmissionAttemptCredentialDescriptorRejected


SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION = 1
SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS = 2 * 60 * 60 * 1000


class SubmissionAttemptCredentialUse(StrEnum):
    SINGLE_USE = "SINGLE_USE"


class SubmissionAttemptCredentialExpiry(StrEnum):
    NON_SLIDING_PRE_CLAIM = "NON_SLIDING_PRE_CLAIM"


class SubmissionAttemptCredentialAllowedTransport(StrEnum):
    POST_BODY = "POST_BODY"
    PROTECTED_SAME_SITE_COOKIE = "PROTECTED_SAME_SITE_COOKIE"


class SubmissionAttemptCredentialForbiddenTransport(StrEnum):
    URL = "URL"
    QUERY_STRING = "QUERY_STRING"
    HEADER_LOG = "HEADER_LOG"
    REFERRER = "REFERRER"


class SubmissionAttemptCredentialForbiddenBinding(StrEnum):
    REPORT_CONTENT = "REPORT_CONTENT"
    TICKET_ID = "TICKET_ID"
    RECOVERY_SECRET = "RECOVERY_SECRET"
    IP_ADDRESS = "IP_ADDRESS"
    USER_AGENT = "USER_AGENT"
    REPORTER_ACCOUNT = "REPORTER_ACCOUNT"
    DEVICE_FINGERPRINT = "DEVICE_FINGERPRINT"


class SubmissionAttemptCredentialDurableRepresentation(StrEnum):
    MINIMUM_VERIFIER_INDEX = "MINIMUM_VERIFIER_INDEX"
    DATABASE_UNIQUENESS_CONSTRAINT = "DATABASE_UNIQUENESS_CONSTRAINT"
    ROW_STATE_VERSION_CHECK = "ROW_STATE_VERSION_CHECK"


class SubmissionAttemptCredentialForbiddenPersistence(StrEnum):
    PLAINTEXT_CREDENTIAL = "PLAINTEXT_CREDENTIAL"
    APPLICATION_LOG = "APPLICATION_LOG"
    AUDIT_LOG = "AUDIT_LOG"
    REQUEST_BODY_LOG = "REQUEST_BODY_LOG"
    REQUEST_HEADER_LOG = "REQUEST_HEADER_LOG"
    REPORTER_METADATA = "REPORTER_METADATA"


SUBMISSION_ATTEMPT_CREDENTIAL_ALLOWED_TRANSPORTS_V1 = (
    SubmissionAttemptCredentialAllowedTransport.POST_BODY,
    SubmissionAttemptCredentialAllowedTransport.PROTECTED_SAME_SITE_COOKIE,
)

SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_TRANSPORTS_V1 = (
    SubmissionAttemptCredentialForbiddenTransport.URL,
    SubmissionAttemptCredentialForbiddenTransport.QUERY_STRING,
    SubmissionAttemptCredentialForbiddenTransport.HEADER_LOG,
    SubmissionAttemptCredentialForbiddenTransport.REFERRER,
)

SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_BINDINGS_V1 = (
    SubmissionAttemptCredentialForbiddenBinding.REPORT_CONTENT,
    SubmissionAttemptCredentialForbiddenBinding.TICKET_ID,
    SubmissionAttemptCredentialForbiddenBinding.RECOVERY_SECRET,
    SubmissionAttemptCredentialForbiddenBinding.IP_ADDRESS,
    SubmissionAttemptCredentialForbiddenBinding.USER_AGENT,
    SubmissionAttemptCredentialForbiddenBinding.REPORTER_ACCOUNT,
    SubmissionAttemptCredentialForbiddenBinding.DEVICE_FINGERPRINT,
)

SUBMISSION_ATTEMPT_CREDENTIAL_DURABLE_REPRESENTATIONS_V1 = (
    SubmissionAttemptCredentialDurableRepresentation.MINIMUM_VERIFIER_INDEX,
    SubmissionAttemptCredentialDurableRepresentation.DATABASE_UNIQUENESS_CONSTRAINT,
    SubmissionAttemptCredentialDurableRepresentation.ROW_STATE_VERSION_CHECK,
)

SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_PERSISTENCE_V1 = (
    SubmissionAttemptCredentialForbiddenPersistence.PLAINTEXT_CREDENTIAL,
    SubmissionAttemptCredentialForbiddenPersistence.APPLICATION_LOG,
    SubmissionAttemptCredentialForbiddenPersistence.AUDIT_LOG,
    SubmissionAttemptCredentialForbiddenPersistence.REQUEST_BODY_LOG,
    SubmissionAttemptCredentialForbiddenPersistence.REQUEST_HEADER_LOG,
    SubmissionAttemptCredentialForbiddenPersistence.REPORTER_METADATA,
)


@dataclass(frozen=True, slots=True)
class SubmissionAttemptCredentialLifetimeProfileV1:
    use: SubmissionAttemptCredentialUse
    expiry: SubmissionAttemptCredentialExpiry
    pre_claim_ttl_ms: int


@dataclass(frozen=True, slots=True)
class SubmissionAttemptCredentialTransportProfileV1:
    allowed_transports: tuple[SubmissionAttemptCredentialAllowedTransport, ...]
    forbidden_transports: tuple[SubmissionAttemptCredentialForbiddenTransport, ...]


@dataclass(frozen=True, slots=True)
class SubmissionAttemptCredentialBindingProfileV1:
    forbidden_bindings: tuple[SubmissionAttemptCredentialForbiddenBinding, ...]


@dataclass(frozen=True, slots=True)
class SubmissionAttemptCredentialPersistenceProfileV1:
    durable_representations: tuple[
        SubmissionAttemptCredentialDurableRepresentation,
        ...,
    ]
    forbidden_persistence: tuple[
        SubmissionAttemptCredentialForbiddenPersistence,
        ...,
    ]


@dataclass(frozen=True, slots=True)
class SubmissionAttemptCredentialProfileV1:
    scheme_version: int
    lifetime: SubmissionAttemptCredentialLifetimeProfileV1
    transport: SubmissionAttemptCredentialTransportProfileV1
    binding: SubmissionAttemptCredentialBindingProfileV1
    persistence: SubmissionAttemptCredentialPersistenceProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionAttemptCredentialProfileV1:
    profile: SubmissionAttemptCredentialProfileV1

    @property
    def generates_credential(self) -> bool:
        return False

    @property
    def verifies_credential(self) -> bool:
        return False

    @property
    def persists_plaintext_credential(self) -> bool:
        return False

    @property
    def installs_cookie(self) -> bool:
        return False

    @property
    def inspects_request(self) -> bool:
        return False

    @property
    def claims_attempt(self) -> bool:
        return False

    @property
    def logs_credential(self) -> bool:
        return False

    @property
    def writes_credential_to_audit(self) -> bool:
        return False

    @property
    def binds_to_reporter_identity(self) -> bool:
        return False

    @property
    def binds_to_network_metadata(self) -> bool:
        return False

    @property
    def creates_reporter_account(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False

    @property
    def authorizes_report_read(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionAttemptCredentialDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_use(value: object) -> SubmissionAttemptCredentialUse:
    if isinstance(value, SubmissionAttemptCredentialUse):
        return value
    _reject()


def _require_expiry(value: object) -> SubmissionAttemptCredentialExpiry:
    if isinstance(value, SubmissionAttemptCredentialExpiry):
        return value
    _reject()


def _require_allowed_transport(
    value: object,
) -> SubmissionAttemptCredentialAllowedTransport:
    if isinstance(value, SubmissionAttemptCredentialAllowedTransport):
        return value
    _reject()


def _require_forbidden_transport(
    value: object,
) -> SubmissionAttemptCredentialForbiddenTransport:
    if isinstance(value, SubmissionAttemptCredentialForbiddenTransport):
        return value
    _reject()


def _require_forbidden_binding(
    value: object,
) -> SubmissionAttemptCredentialForbiddenBinding:
    if isinstance(value, SubmissionAttemptCredentialForbiddenBinding):
        return value
    _reject()


def _require_durable_representation(
    value: object,
) -> SubmissionAttemptCredentialDurableRepresentation:
    if isinstance(value, SubmissionAttemptCredentialDurableRepresentation):
        return value
    _reject()


def _require_forbidden_persistence(
    value: object,
) -> SubmissionAttemptCredentialForbiddenPersistence:
    if isinstance(value, SubmissionAttemptCredentialForbiddenPersistence):
        return value
    _reject()


def _require_allowed_transports(
    value: object,
) -> tuple[SubmissionAttemptCredentialAllowedTransport, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_allowed_transport(item) for item in value)
    if normalized != SUBMISSION_ATTEMPT_CREDENTIAL_ALLOWED_TRANSPORTS_V1:
        _reject()
    return normalized


def _require_forbidden_transports(
    value: object,
) -> tuple[SubmissionAttemptCredentialForbiddenTransport, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_transport(item) for item in value)
    if normalized != SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_TRANSPORTS_V1:
        _reject()
    return normalized


def _require_forbidden_bindings(
    value: object,
) -> tuple[SubmissionAttemptCredentialForbiddenBinding, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_binding(item) for item in value)
    if normalized != SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_BINDINGS_V1:
        _reject()
    return normalized


def _require_durable_representations(
    value: object,
) -> tuple[SubmissionAttemptCredentialDurableRepresentation, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_durable_representation(item) for item in value
    )
    if normalized != SUBMISSION_ATTEMPT_CREDENTIAL_DURABLE_REPRESENTATIONS_V1:
        _reject()
    return normalized


def _require_forbidden_persistence_fields(
    value: object,
) -> tuple[SubmissionAttemptCredentialForbiddenPersistence, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_persistence(item) for item in value)
    if normalized != SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_PERSISTENCE_V1:
        _reject()
    return normalized


def validate_submission_attempt_credential_lifetime_profile_v1(
    lifetime: SubmissionAttemptCredentialLifetimeProfileV1,
) -> SubmissionAttemptCredentialLifetimeProfileV1:
    if type(lifetime) is not SubmissionAttemptCredentialLifetimeProfileV1:
        _reject()
    return SubmissionAttemptCredentialLifetimeProfileV1(
        use=_require_use(lifetime.use),
        expiry=_require_expiry(lifetime.expiry),
        pre_claim_ttl_ms=_require_uint_exact(
            lifetime.pre_claim_ttl_ms,
            expected=SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS,
        ),
    )


def validate_submission_attempt_credential_transport_profile_v1(
    transport: SubmissionAttemptCredentialTransportProfileV1,
) -> SubmissionAttemptCredentialTransportProfileV1:
    if type(transport) is not SubmissionAttemptCredentialTransportProfileV1:
        _reject()
    return SubmissionAttemptCredentialTransportProfileV1(
        allowed_transports=_require_allowed_transports(
            transport.allowed_transports
        ),
        forbidden_transports=_require_forbidden_transports(
            transport.forbidden_transports
        ),
    )


def validate_submission_attempt_credential_binding_profile_v1(
    binding: SubmissionAttemptCredentialBindingProfileV1,
) -> SubmissionAttemptCredentialBindingProfileV1:
    if type(binding) is not SubmissionAttemptCredentialBindingProfileV1:
        _reject()
    return SubmissionAttemptCredentialBindingProfileV1(
        forbidden_bindings=_require_forbidden_bindings(
            binding.forbidden_bindings
        ),
    )


def validate_submission_attempt_credential_persistence_profile_v1(
    persistence: SubmissionAttemptCredentialPersistenceProfileV1,
) -> SubmissionAttemptCredentialPersistenceProfileV1:
    if type(persistence) is not SubmissionAttemptCredentialPersistenceProfileV1:
        _reject()
    return SubmissionAttemptCredentialPersistenceProfileV1(
        durable_representations=_require_durable_representations(
            persistence.durable_representations
        ),
        forbidden_persistence=_require_forbidden_persistence_fields(
            persistence.forbidden_persistence
        ),
    )


def validate_submission_attempt_credential_profile_v1(
    profile: SubmissionAttemptCredentialProfileV1,
) -> StructurallyValidSubmissionAttemptCredentialProfileV1:
    if type(profile) is not SubmissionAttemptCredentialProfileV1:
        _reject()
    normalized = SubmissionAttemptCredentialProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION,
        ),
        lifetime=validate_submission_attempt_credential_lifetime_profile_v1(
            profile.lifetime
        ),
        transport=validate_submission_attempt_credential_transport_profile_v1(
            profile.transport
        ),
        binding=validate_submission_attempt_credential_binding_profile_v1(
            profile.binding
        ),
        persistence=(
            validate_submission_attempt_credential_persistence_profile_v1(
                profile.persistence
            )
        ),
    )
    return StructurallyValidSubmissionAttemptCredentialProfileV1(
        profile=normalized
    )


def expected_submission_attempt_credential_profile_v1(
) -> SubmissionAttemptCredentialProfileV1:
    """Return only the approved attempt-credential policy metadata."""

    return SubmissionAttemptCredentialProfileV1(
        scheme_version=SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION,
        lifetime=SubmissionAttemptCredentialLifetimeProfileV1(
            use=SubmissionAttemptCredentialUse.SINGLE_USE,
            expiry=SubmissionAttemptCredentialExpiry.NON_SLIDING_PRE_CLAIM,
            pre_claim_ttl_ms=SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS,
        ),
        transport=SubmissionAttemptCredentialTransportProfileV1(
            allowed_transports=(
                SUBMISSION_ATTEMPT_CREDENTIAL_ALLOWED_TRANSPORTS_V1
            ),
            forbidden_transports=(
                SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_TRANSPORTS_V1
            ),
        ),
        binding=SubmissionAttemptCredentialBindingProfileV1(
            forbidden_bindings=(
                SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_BINDINGS_V1
            ),
        ),
        persistence=SubmissionAttemptCredentialPersistenceProfileV1(
            durable_representations=(
                SUBMISSION_ATTEMPT_CREDENTIAL_DURABLE_REPRESENTATIONS_V1
            ),
            forbidden_persistence=(
                SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_PERSISTENCE_V1
            ),
        ),
    )
