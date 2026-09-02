"""Inert recovery retrieval flow descriptors from docs/05, docs/21, docs/24.

This module validates only static checkpoint ordering metadata for the
approved Response Note retrieval flow. It does not handle requests, validate
CAPTCHA, validate credentials, append audit events, verify receipts, query
state, mutate first-read state, call the Key Service, decrypt responses, render
plaintext, log credentials, expose endpoints, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryRetrievalDescriptorRejected


RECOVERY_RETRIEVAL_PROFILE_VERSION = 1


class RecoveryRetrievalPhase(StrEnum):
    ACCEPT_POST_INPUT = "ACCEPT_POST_INPUT"
    VALIDATE_CHALLENGE_AND_CREDENTIALS = (
        "VALIDATE_CHALLENGE_AND_CREDENTIALS"
    )
    OBTAIN_RETRIEVAL_AUDIT_RECEIPT = "OBTAIN_RETRIEVAL_AUDIT_RECEIPT"
    LOCK_AND_VALIDATE_ELIGIBILITY = "LOCK_AND_VALIDATE_ELIGIBILITY"
    ARM_OR_CONVERT_RESPONSE_EXPIRY = "ARM_OR_CONVERT_RESPONSE_EXPIRY"
    DECRYPT_WITH_SCOPED_AUTHORIZATION = "DECRYPT_WITH_SCOPED_AUTHORIZATION"
    VALIDATE_AND_RENDER_CANONICAL_TEXT = "VALIDATE_AND_RENDER_CANONICAL_TEXT"
    APPEND_CONTENT_FREE_OUTCOME = "APPEND_CONTENT_FREE_OUTCOME"


class RecoveryRetrievalCheckpoint(StrEnum):
    POST_ONLY_INPUT_RECEIVED = "POST_ONLY_INPUT_RECEIVED"
    CAPTCHA_AND_VERIFIER_APPROVED = "CAPTCHA_AND_VERIFIER_APPROVED"
    RESPONSE_RETRIEVAL_REQUESTED_RECEIPT_DURABLE = (
        "RESPONSE_RETRIEVAL_REQUESTED_RECEIPT_DURABLE"
    )
    SERVER_STATE_AND_VERSION_LOCKED = "SERVER_STATE_AND_VERSION_LOCKED"
    IMMUTABLE_EXPIRY_CONFIRMED = "IMMUTABLE_EXPIRY_CONFIRMED"
    KEY_SERVICE_DECRYPT_CONFIRMED = "KEY_SERVICE_DECRYPT_CONFIRMED"
    CANONICAL_TEXT_READY_WITH_NO_STORE = "CANONICAL_TEXT_READY_WITH_NO_STORE"
    CONTENT_FREE_OUTCOME_APPENDED = "CONTENT_FREE_OUTCOME_APPENDED"


class RecoveryRetrievalRequirement(StrEnum):
    TICKET_ID_SECRET_AND_CAPTCHA_POST_ONLY = (
        "TICKET_ID_SECRET_AND_CAPTCHA_POST_ONLY"
    )
    SECRETS_NEVER_IN_URL = "SECRETS_NEVER_IN_URL"
    SELF_HOSTED_CAPTCHA_REQUIRED = "SELF_HOSTED_CAPTCHA_REQUIRED"
    APPROVED_VERIFIER_REQUIRED = "APPROVED_VERIFIER_REQUIRED"
    GENERIC_EXTERNAL_NON_SUCCESS_REQUIRED = (
        "GENERIC_EXTERNAL_NON_SUCCESS_REQUIRED"
    )
    RETRIEVAL_REQUESTED_RECEIPT_REQUIRED = (
        "RETRIEVAL_REQUESTED_RECEIPT_REQUIRED"
    )
    SERVER_TIME_STATE_LOCK_REQUIRED = "SERVER_TIME_STATE_LOCK_REQUIRED"
    ELIGIBILITY_REVALIDATED_AFTER_RECEIPT = (
        "ELIGIBILITY_REVALIDATED_AFTER_RECEIPT"
    )
    FIRST_READ_TIMESTAMP_IMMUTABLE = "FIRST_READ_TIMESTAMP_IMMUTABLE"
    EXISTING_READ_WINDOW_NOT_EXTENDED = "EXISTING_READ_WINDOW_NOT_EXTENDED"
    KEY_SERVICE_EXPIRY_MATCH_REQUIRED = "KEY_SERVICE_EXPIRY_MATCH_REQUIRED"
    RECOVERY_AUTHORIZATION_OPAQUE_AND_SCOPED = (
        "RECOVERY_AUTHORIZATION_OPAQUE_AND_SCOPED"
    )
    RECOVERY_SECRET_NOT_SENT_TO_KEY_SERVICE = (
        "RECOVERY_SECRET_NOT_SENT_TO_KEY_SERVICE"
    )
    FIXED_FRAME_VALIDATED_BEFORE_TEXT_RETURN = (
        "FIXED_FRAME_VALIDATED_BEFORE_TEXT_RETURN"
    )
    NO_STORE_NO_REFERRER_RESPONSE_REQUIRED = (
        "NO_STORE_NO_REFERRER_RESPONSE_REQUIRED"
    )
    OUTCOME_EXCLUDES_CREDENTIALS_AND_PLAINTEXT = (
        "OUTCOME_EXCLUDES_CREDENTIALS_AND_PLAINTEXT"
    )


class RecoveryRetrievalForbiddenCapability(StrEnum):
    HANDLES_REQUEST = "HANDLES_REQUEST"
    VALIDATES_CAPTCHA = "VALIDATES_CAPTCHA"
    VALIDATES_CREDENTIALS = "VALIDATES_CREDENTIALS"
    APPENDS_AUDIT_EVENT = "APPENDS_AUDIT_EVENT"
    VERIFIES_AUDIT_RECEIPT = "VERIFIES_AUDIT_RECEIPT"
    QUERIES_RESPONSE_STATE = "QUERIES_RESPONSE_STATE"
    MUTATES_FIRST_READ = "MUTATES_FIRST_READ"
    CALLS_KEY_SERVICE = "CALLS_KEY_SERVICE"
    DECRYPTS_RESPONSE = "DECRYPTS_RESPONSE"
    VALIDATES_PLAINTEXT_FRAME = "VALIDATES_PLAINTEXT_FRAME"
    RENDERS_RESPONSE = "RENDERS_RESPONSE"
    PERSISTS_PLAINTEXT = "PERSISTS_PLAINTEXT"
    LOGS_CREDENTIALS_OR_PLAINTEXT = "LOGS_CREDENTIALS_OR_PLAINTEXT"
    RETURNS_DISTINCT_FAILURE = "RETURNS_DISTINCT_FAILURE"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_RECOVERY = "AUTHORIZES_RECOVERY"


RECOVERY_RETRIEVAL_PHASES_V1 = (
    RecoveryRetrievalPhase.ACCEPT_POST_INPUT,
    RecoveryRetrievalPhase.VALIDATE_CHALLENGE_AND_CREDENTIALS,
    RecoveryRetrievalPhase.OBTAIN_RETRIEVAL_AUDIT_RECEIPT,
    RecoveryRetrievalPhase.LOCK_AND_VALIDATE_ELIGIBILITY,
    RecoveryRetrievalPhase.ARM_OR_CONVERT_RESPONSE_EXPIRY,
    RecoveryRetrievalPhase.DECRYPT_WITH_SCOPED_AUTHORIZATION,
    RecoveryRetrievalPhase.VALIDATE_AND_RENDER_CANONICAL_TEXT,
    RecoveryRetrievalPhase.APPEND_CONTENT_FREE_OUTCOME,
)

RECOVERY_RETRIEVAL_CHECKPOINTS_V1 = (
    RecoveryRetrievalCheckpoint.POST_ONLY_INPUT_RECEIVED,
    RecoveryRetrievalCheckpoint.CAPTCHA_AND_VERIFIER_APPROVED,
    RecoveryRetrievalCheckpoint.RESPONSE_RETRIEVAL_REQUESTED_RECEIPT_DURABLE,
    RecoveryRetrievalCheckpoint.SERVER_STATE_AND_VERSION_LOCKED,
    RecoveryRetrievalCheckpoint.IMMUTABLE_EXPIRY_CONFIRMED,
    RecoveryRetrievalCheckpoint.KEY_SERVICE_DECRYPT_CONFIRMED,
    RecoveryRetrievalCheckpoint.CANONICAL_TEXT_READY_WITH_NO_STORE,
    RecoveryRetrievalCheckpoint.CONTENT_FREE_OUTCOME_APPENDED,
)

RECOVERY_RETRIEVAL_FORBIDDEN_CAPABILITIES_V1 = (
    RecoveryRetrievalForbiddenCapability.HANDLES_REQUEST,
    RecoveryRetrievalForbiddenCapability.VALIDATES_CAPTCHA,
    RecoveryRetrievalForbiddenCapability.VALIDATES_CREDENTIALS,
    RecoveryRetrievalForbiddenCapability.APPENDS_AUDIT_EVENT,
    RecoveryRetrievalForbiddenCapability.VERIFIES_AUDIT_RECEIPT,
    RecoveryRetrievalForbiddenCapability.QUERIES_RESPONSE_STATE,
    RecoveryRetrievalForbiddenCapability.MUTATES_FIRST_READ,
    RecoveryRetrievalForbiddenCapability.CALLS_KEY_SERVICE,
    RecoveryRetrievalForbiddenCapability.DECRYPTS_RESPONSE,
    RecoveryRetrievalForbiddenCapability.VALIDATES_PLAINTEXT_FRAME,
    RecoveryRetrievalForbiddenCapability.RENDERS_RESPONSE,
    RecoveryRetrievalForbiddenCapability.PERSISTS_PLAINTEXT,
    RecoveryRetrievalForbiddenCapability.LOGS_CREDENTIALS_OR_PLAINTEXT,
    RecoveryRetrievalForbiddenCapability.RETURNS_DISTINCT_FAILURE,
    RecoveryRetrievalForbiddenCapability.EXPOSES_ENDPOINT,
    RecoveryRetrievalForbiddenCapability.AUTHORIZES_RECOVERY,
)


@dataclass(frozen=True, slots=True)
class RecoveryRetrievalCheckpointDescriptorV1:
    sequence_index: int
    phase: RecoveryRetrievalPhase
    checkpoint: RecoveryRetrievalCheckpoint
    requirements: tuple[RecoveryRetrievalRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryRetrievalProfileV1:
    scheme_version: int
    checkpoints: tuple[RecoveryRetrievalCheckpointDescriptorV1, ...]
    forbidden_capabilities: tuple[RecoveryRetrievalForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryRetrievalProfileV1:
    profile: RecoveryRetrievalProfileV1

    @property
    def handles_request(self) -> bool:
        return False

    @property
    def validates_captcha(self) -> bool:
        return False

    @property
    def validates_credentials(self) -> bool:
        return False

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def verifies_audit_receipt(self) -> bool:
        return False

    @property
    def queries_response_state(self) -> bool:
        return False

    @property
    def mutates_first_read(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def decrypts_response(self) -> bool:
        return False

    @property
    def validates_plaintext_frame(self) -> bool:
        return False

    @property
    def renders_response(self) -> bool:
        return False

    @property
    def persists_plaintext(self) -> bool:
        return False

    @property
    def logs_credentials_or_plaintext(self) -> bool:
        return False

    @property
    def returns_distinct_failure(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryRetrievalDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_phase(value: object) -> RecoveryRetrievalPhase:
    if isinstance(value, RecoveryRetrievalPhase):
        return value
    _reject()


def _require_checkpoint(value: object) -> RecoveryRetrievalCheckpoint:
    if isinstance(value, RecoveryRetrievalCheckpoint):
        return value
    _reject()


def _require_requirement(value: object) -> RecoveryRetrievalRequirement:
    if isinstance(value, RecoveryRetrievalRequirement):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> RecoveryRetrievalForbiddenCapability:
    if isinstance(value, RecoveryRetrievalForbiddenCapability):
        return value
    _reject()


def _require_requirements(
    value: object,
) -> tuple[RecoveryRetrievalRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    return tuple(_require_requirement(item) for item in value)


def _expected_checkpoint_by_index(
    index: int,
) -> RecoveryRetrievalCheckpointDescriptorV1:
    return RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1[index]


def _require_checkpoint_descriptor(
    value: object,
) -> RecoveryRetrievalCheckpointDescriptorV1:
    if type(value) is not RecoveryRetrievalCheckpointDescriptorV1:
        _reject()
    sequence_index = _require_uint_exact(
        value.sequence_index,
        expected=value.sequence_index,
    )
    if not 0 <= sequence_index < len(RECOVERY_RETRIEVAL_CHECKPOINTS_V1):
        _reject()
    expected = _expected_checkpoint_by_index(sequence_index)
    normalized = RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=sequence_index,
        phase=_require_phase(value.phase),
        checkpoint=_require_checkpoint(value.checkpoint),
        requirements=_require_requirements(value.requirements),
    )
    if normalized != expected:
        _reject()
    return normalized


def _require_checkpoint_sequence(
    value: object,
) -> tuple[RecoveryRetrievalCheckpointDescriptorV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_checkpoint_descriptor(item) for item in value)
    if normalized != RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[RecoveryRetrievalForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != RECOVERY_RETRIEVAL_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


def validate_recovery_retrieval_checkpoint_descriptor_v1(
    descriptor: RecoveryRetrievalCheckpointDescriptorV1,
) -> RecoveryRetrievalCheckpointDescriptorV1:
    return _require_checkpoint_descriptor(descriptor)


def validate_recovery_retrieval_profile_v1(
    profile: RecoveryRetrievalProfileV1,
) -> StructurallyValidRecoveryRetrievalProfileV1:
    if type(profile) is not RecoveryRetrievalProfileV1:
        _reject()
    normalized = RecoveryRetrievalProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_RETRIEVAL_PROFILE_VERSION,
        ),
        checkpoints=_require_checkpoint_sequence(profile.checkpoints),
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        ),
    )
    if normalized != expected_recovery_retrieval_profile_v1():
        _reject()
    return StructurallyValidRecoveryRetrievalProfileV1(normalized)


RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1 = (
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=0,
        phase=RecoveryRetrievalPhase.ACCEPT_POST_INPUT,
        checkpoint=RecoveryRetrievalCheckpoint.POST_ONLY_INPUT_RECEIVED,
        requirements=(
            RecoveryRetrievalRequirement.TICKET_ID_SECRET_AND_CAPTCHA_POST_ONLY,
            RecoveryRetrievalRequirement.SECRETS_NEVER_IN_URL,
            RecoveryRetrievalRequirement.GENERIC_EXTERNAL_NON_SUCCESS_REQUIRED,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=1,
        phase=RecoveryRetrievalPhase.VALIDATE_CHALLENGE_AND_CREDENTIALS,
        checkpoint=RecoveryRetrievalCheckpoint.CAPTCHA_AND_VERIFIER_APPROVED,
        requirements=(
            RecoveryRetrievalRequirement.SELF_HOSTED_CAPTCHA_REQUIRED,
            RecoveryRetrievalRequirement.APPROVED_VERIFIER_REQUIRED,
            RecoveryRetrievalRequirement.GENERIC_EXTERNAL_NON_SUCCESS_REQUIRED,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=2,
        phase=RecoveryRetrievalPhase.OBTAIN_RETRIEVAL_AUDIT_RECEIPT,
        checkpoint=(
            RecoveryRetrievalCheckpoint.
            RESPONSE_RETRIEVAL_REQUESTED_RECEIPT_DURABLE
        ),
        requirements=(
            RecoveryRetrievalRequirement.RETRIEVAL_REQUESTED_RECEIPT_REQUIRED,
            RecoveryRetrievalRequirement.OUTCOME_EXCLUDES_CREDENTIALS_AND_PLAINTEXT,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=3,
        phase=RecoveryRetrievalPhase.LOCK_AND_VALIDATE_ELIGIBILITY,
        checkpoint=RecoveryRetrievalCheckpoint.SERVER_STATE_AND_VERSION_LOCKED,
        requirements=(
            RecoveryRetrievalRequirement.SERVER_TIME_STATE_LOCK_REQUIRED,
            RecoveryRetrievalRequirement.ELIGIBILITY_REVALIDATED_AFTER_RECEIPT,
            RecoveryRetrievalRequirement.FIRST_READ_TIMESTAMP_IMMUTABLE,
            RecoveryRetrievalRequirement.EXISTING_READ_WINDOW_NOT_EXTENDED,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=4,
        phase=RecoveryRetrievalPhase.ARM_OR_CONVERT_RESPONSE_EXPIRY,
        checkpoint=RecoveryRetrievalCheckpoint.IMMUTABLE_EXPIRY_CONFIRMED,
        requirements=(
            RecoveryRetrievalRequirement.KEY_SERVICE_EXPIRY_MATCH_REQUIRED,
            RecoveryRetrievalRequirement.FIRST_READ_TIMESTAMP_IMMUTABLE,
            RecoveryRetrievalRequirement.EXISTING_READ_WINDOW_NOT_EXTENDED,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=5,
        phase=RecoveryRetrievalPhase.DECRYPT_WITH_SCOPED_AUTHORIZATION,
        checkpoint=RecoveryRetrievalCheckpoint.KEY_SERVICE_DECRYPT_CONFIRMED,
        requirements=(
            RecoveryRetrievalRequirement.RECOVERY_AUTHORIZATION_OPAQUE_AND_SCOPED,
            RecoveryRetrievalRequirement.RECOVERY_SECRET_NOT_SENT_TO_KEY_SERVICE,
            RecoveryRetrievalRequirement.KEY_SERVICE_EXPIRY_MATCH_REQUIRED,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=6,
        phase=RecoveryRetrievalPhase.VALIDATE_AND_RENDER_CANONICAL_TEXT,
        checkpoint=RecoveryRetrievalCheckpoint.CANONICAL_TEXT_READY_WITH_NO_STORE,
        requirements=(
            RecoveryRetrievalRequirement.FIXED_FRAME_VALIDATED_BEFORE_TEXT_RETURN,
            RecoveryRetrievalRequirement.NO_STORE_NO_REFERRER_RESPONSE_REQUIRED,
        ),
    ),
    RecoveryRetrievalCheckpointDescriptorV1(
        sequence_index=7,
        phase=RecoveryRetrievalPhase.APPEND_CONTENT_FREE_OUTCOME,
        checkpoint=RecoveryRetrievalCheckpoint.CONTENT_FREE_OUTCOME_APPENDED,
        requirements=(
            RecoveryRetrievalRequirement.OUTCOME_EXCLUDES_CREDENTIALS_AND_PLAINTEXT,
            RecoveryRetrievalRequirement.GENERIC_EXTERNAL_NON_SUCCESS_REQUIRED,
        ),
    ),
)


def expected_recovery_retrieval_profile_v1() -> RecoveryRetrievalProfileV1:
    return RecoveryRetrievalProfileV1(
        scheme_version=RECOVERY_RETRIEVAL_PROFILE_VERSION,
        checkpoints=RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1,
        forbidden_capabilities=RECOVERY_RETRIEVAL_FORBIDDEN_CAPABILITIES_V1,
    )
