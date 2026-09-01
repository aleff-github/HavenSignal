"""Inert submission-acceptance checkpoint descriptors from docs/20.

This module validates only static phase/checkpoint ordering metadata for the
approved submission acceptance protocol. It does not parse requests, validate
credentials, claim attempts, append audit events, verify receipts, create
keys, encrypt, persist records, render responses, reconcile attempts, expose
endpoints, or authorize submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SubmissionAcceptanceCheckpointDescriptorRejected


SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION = 1


class SubmissionAcceptancePhase(StrEnum):
    SERVE_INERT_FORM = "SERVE_INERT_FORM"
    ADMIT_REQUEST = "ADMIT_REQUEST"
    VALIDATE_TRANSIENT_INPUT = "VALIDATE_TRANSIENT_INPUT"
    OBTAIN_PRE_ACTION_AUDIT_EVIDENCE = "OBTAIN_PRE_ACTION_AUDIT_EVIDENCE"
    PROTECT_AND_STAGE = "PROTECT_AND_STAGE"
    AUDIT_AND_COMMIT_ACCEPTANCE = "AUDIT_AND_COMMIT_ACCEPTANCE"
    RECONCILE_WITHOUT_PLAINTEXT = "RECONCILE_WITHOUT_PLAINTEXT"


class SubmissionAcceptanceCheckpoint(StrEnum):
    FORM_SURFACE_READY = "FORM_SURFACE_READY"
    ATTEMPT_CLAIMED_BEFORE_PIPELINE = "ATTEMPT_CLAIMED_BEFORE_PIPELINE"
    TRANSIENT_INPUT_VALIDATED = "TRANSIENT_INPUT_VALIDATED"
    REQUESTED_RECEIPT_DURABLE_BEFORE_KEY_OR_CONTENT = (
        "REQUESTED_RECEIPT_DURABLE_BEFORE_KEY_OR_CONTENT"
    )
    CIPHERTEXT_AND_METADATA_STAGED_NON_VISIBLE = (
        "CIPHERTEXT_AND_METADATA_STAGED_NON_VISIBLE"
    )
    RECEIVED_RECEIPT_BOUND_TO_SEALED_COMMIT = (
        "RECEIVED_RECEIPT_BOUND_TO_SEALED_COMMIT"
    )
    NONTERMINAL_ATTEMPT_FINISHED_OR_ABORTED = (
        "NONTERMINAL_ATTEMPT_FINISHED_OR_ABORTED"
    )


class SubmissionAcceptanceRequirement(StrEnum):
    SELF_HOSTED_NO_THIRD_PARTY_SURFACE = "SELF_HOSTED_NO_THIRD_PARTY_SURFACE"
    NO_REPORTER_IDENTITY_BINDING = "NO_REPORTER_IDENTITY_BINDING"
    NO_STORE_RESPONSE_HEADERS = "NO_STORE_RESPONSE_HEADERS"
    FIXED_POST_URL_WITHOUT_QUERY_SECRET = "FIXED_POST_URL_WITHOUT_QUERY_SECRET"
    OUTER_BODY_BOUNDARY_ACCEPTED = "OUTER_BODY_BOUNDARY_ACCEPTED"
    CSRF_ATTEMPT_AND_CHALLENGE_VALID = "CSRF_ATTEMPT_AND_CHALLENGE_VALID"
    SINGLE_DATABASE_OWNER = "SINGLE_DATABASE_OWNER"
    SERVER_OBSERVED_LIMITS_ENFORCED = "SERVER_OBSERVED_LIMITS_ENFORCED"
    ORIGINAL_FILENAME_DISCARDED = "ORIGINAL_FILENAME_DISCARDED"
    MEDIA_DECLARATIONS_DISTRUSTED = "MEDIA_DECLARATIONS_DISTRUSTED"
    SANDBOX_DECISION_READY = "SANDBOX_DECISION_READY"
    REQUESTED_RECEIPT_DURABLE = "REQUESTED_RECEIPT_DURABLE"
    REQUESTED_RECEIPT_CONTEXT_VALID = "REQUESTED_RECEIPT_CONTEXT_VALID"
    NEW_REPORT_PROTECTION_CAPABILITY_READY = (
        "NEW_REPORT_PROTECTION_CAPABILITY_READY"
    )
    CIPHERTEXT_OBJECTS_DURABLY_VERIFIED = "CIPHERTEXT_OBJECTS_DURABLY_VERIFIED"
    METADATA_STAGED_NON_VISIBLE = "METADATA_STAGED_NON_VISIBLE"
    RECEIVED_RECEIPT_DURABLE = "RECEIVED_RECEIPT_DURABLE"
    RECEIVED_RECEIPT_CONTEXT_VALID = "RECEIVED_RECEIPT_CONTEXT_VALID"
    STATE_VERSION_RELOCKED = "STATE_VERSION_RELOCKED"
    SEALED_COMMIT_READY = "SEALED_COMMIT_READY"
    NONTERMINAL_ATTEMPT_SELECTED_BY_STATE_AND_TIME = (
        "NONTERMINAL_ATTEMPT_SELECTED_BY_STATE_AND_TIME"
    )
    EVIDENCED_FINISH_OR_SCOPED_ABORT_ONLY = "EVIDENCED_FINISH_OR_SCOPED_ABORT_ONLY"


class SubmissionAcceptanceForbiddenCapability(StrEnum):
    REQUEST_PARSING = "REQUEST_PARSING"
    CREDENTIAL_VALIDATION = "CREDENTIAL_VALIDATION"
    ATTEMPT_CLAIMING = "ATTEMPT_CLAIMING"
    AUDIT_APPEND = "AUDIT_APPEND"
    RECEIPT_VERIFICATION = "RECEIPT_VERIFICATION"
    KEY_SERVICE_CALL = "KEY_SERVICE_CALL"
    ENCRYPTION = "ENCRYPTION"
    STORAGE_WRITE = "STORAGE_WRITE"
    DATABASE_COMMIT = "DATABASE_COMMIT"
    RESPONSE_RENDERING = "RESPONSE_RENDERING"
    RECONCILER_EXECUTION = "RECONCILER_EXECUTION"
    ENDPOINT_EXPOSURE = "ENDPOINT_EXPOSURE"
    SUBMISSION_AUTHORIZATION = "SUBMISSION_AUTHORIZATION"


SUBMISSION_ACCEPTANCE_PHASES_V1 = (
    SubmissionAcceptancePhase.SERVE_INERT_FORM,
    SubmissionAcceptancePhase.ADMIT_REQUEST,
    SubmissionAcceptancePhase.VALIDATE_TRANSIENT_INPUT,
    SubmissionAcceptancePhase.OBTAIN_PRE_ACTION_AUDIT_EVIDENCE,
    SubmissionAcceptancePhase.PROTECT_AND_STAGE,
    SubmissionAcceptancePhase.AUDIT_AND_COMMIT_ACCEPTANCE,
    SubmissionAcceptancePhase.RECONCILE_WITHOUT_PLAINTEXT,
)

SUBMISSION_ACCEPTANCE_CHECKPOINTS_V1 = (
    SubmissionAcceptanceCheckpoint.FORM_SURFACE_READY,
    SubmissionAcceptanceCheckpoint.ATTEMPT_CLAIMED_BEFORE_PIPELINE,
    SubmissionAcceptanceCheckpoint.TRANSIENT_INPUT_VALIDATED,
    (
        SubmissionAcceptanceCheckpoint.
        REQUESTED_RECEIPT_DURABLE_BEFORE_KEY_OR_CONTENT
    ),
    SubmissionAcceptanceCheckpoint.CIPHERTEXT_AND_METADATA_STAGED_NON_VISIBLE,
    SubmissionAcceptanceCheckpoint.RECEIVED_RECEIPT_BOUND_TO_SEALED_COMMIT,
    SubmissionAcceptanceCheckpoint.NONTERMINAL_ATTEMPT_FINISHED_OR_ABORTED,
)

SUBMISSION_ACCEPTANCE_FORBIDDEN_CAPABILITIES_V1 = (
    SubmissionAcceptanceForbiddenCapability.REQUEST_PARSING,
    SubmissionAcceptanceForbiddenCapability.CREDENTIAL_VALIDATION,
    SubmissionAcceptanceForbiddenCapability.ATTEMPT_CLAIMING,
    SubmissionAcceptanceForbiddenCapability.AUDIT_APPEND,
    SubmissionAcceptanceForbiddenCapability.RECEIPT_VERIFICATION,
    SubmissionAcceptanceForbiddenCapability.KEY_SERVICE_CALL,
    SubmissionAcceptanceForbiddenCapability.ENCRYPTION,
    SubmissionAcceptanceForbiddenCapability.STORAGE_WRITE,
    SubmissionAcceptanceForbiddenCapability.DATABASE_COMMIT,
    SubmissionAcceptanceForbiddenCapability.RESPONSE_RENDERING,
    SubmissionAcceptanceForbiddenCapability.RECONCILER_EXECUTION,
    SubmissionAcceptanceForbiddenCapability.ENDPOINT_EXPOSURE,
    SubmissionAcceptanceForbiddenCapability.SUBMISSION_AUTHORIZATION,
)


@dataclass(frozen=True, slots=True)
class SubmissionAcceptanceCheckpointDescriptorV1:
    sequence_index: int
    phase: SubmissionAcceptancePhase
    checkpoint: SubmissionAcceptanceCheckpoint
    requirements: tuple[SubmissionAcceptanceRequirement, ...]


@dataclass(frozen=True, slots=True)
class SubmissionAcceptanceCheckpointProfileV1:
    scheme_version: int
    checkpoints: tuple[SubmissionAcceptanceCheckpointDescriptorV1, ...]
    forbidden_capabilities: tuple[SubmissionAcceptanceForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionAcceptanceCheckpointProfileV1:
    profile: SubmissionAcceptanceCheckpointProfileV1

    @property
    def parses_request(self) -> bool:
        return False

    @property
    def validates_credential(self) -> bool:
        return False

    @property
    def claims_attempt(self) -> bool:
        return False

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def verifies_receipt(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def encrypts_content(self) -> bool:
        return False

    @property
    def persists_records(self) -> bool:
        return False

    @property
    def renders_response(self) -> bool:
        return False

    @property
    def reconciles_attempts(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionAcceptanceCheckpointDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_phase(value: object) -> SubmissionAcceptancePhase:
    if isinstance(value, SubmissionAcceptancePhase):
        return value
    _reject()


def _require_checkpoint(value: object) -> SubmissionAcceptanceCheckpoint:
    if isinstance(value, SubmissionAcceptanceCheckpoint):
        return value
    _reject()


def _require_requirement(value: object) -> SubmissionAcceptanceRequirement:
    if isinstance(value, SubmissionAcceptanceRequirement):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> SubmissionAcceptanceForbiddenCapability:
    if isinstance(value, SubmissionAcceptanceForbiddenCapability):
        return value
    _reject()


def _require_requirements(
    value: object,
) -> tuple[SubmissionAcceptanceRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    return tuple(_require_requirement(item) for item in value)


def _expected_checkpoint_by_index(
    index: int,
) -> SubmissionAcceptanceCheckpointDescriptorV1:
    return SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1[index]


def _require_checkpoint_descriptor(
    value: object,
) -> SubmissionAcceptanceCheckpointDescriptorV1:
    if type(value) is not SubmissionAcceptanceCheckpointDescriptorV1:
        _reject()
    sequence_index = _require_uint_exact(
        value.sequence_index,
        expected=value.sequence_index,
    )
    if not 0 <= sequence_index < len(SUBMISSION_ACCEPTANCE_CHECKPOINTS_V1):
        _reject()
    expected = _expected_checkpoint_by_index(sequence_index)
    normalized = SubmissionAcceptanceCheckpointDescriptorV1(
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
) -> tuple[SubmissionAcceptanceCheckpointDescriptorV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_checkpoint_descriptor(item) for item in value)
    if normalized != SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[SubmissionAcceptanceForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != SUBMISSION_ACCEPTANCE_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1 = (
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=0,
        phase=SubmissionAcceptancePhase.SERVE_INERT_FORM,
        checkpoint=SubmissionAcceptanceCheckpoint.FORM_SURFACE_READY,
        requirements=(
            SubmissionAcceptanceRequirement.SELF_HOSTED_NO_THIRD_PARTY_SURFACE,
            SubmissionAcceptanceRequirement.NO_REPORTER_IDENTITY_BINDING,
            SubmissionAcceptanceRequirement.NO_STORE_RESPONSE_HEADERS,
        ),
    ),
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=1,
        phase=SubmissionAcceptancePhase.ADMIT_REQUEST,
        checkpoint=(
            SubmissionAcceptanceCheckpoint.ATTEMPT_CLAIMED_BEFORE_PIPELINE
        ),
        requirements=(
            SubmissionAcceptanceRequirement.FIXED_POST_URL_WITHOUT_QUERY_SECRET,
            SubmissionAcceptanceRequirement.OUTER_BODY_BOUNDARY_ACCEPTED,
            SubmissionAcceptanceRequirement.CSRF_ATTEMPT_AND_CHALLENGE_VALID,
            SubmissionAcceptanceRequirement.SINGLE_DATABASE_OWNER,
        ),
    ),
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=2,
        phase=SubmissionAcceptancePhase.VALIDATE_TRANSIENT_INPUT,
        checkpoint=SubmissionAcceptanceCheckpoint.TRANSIENT_INPUT_VALIDATED,
        requirements=(
            SubmissionAcceptanceRequirement.SERVER_OBSERVED_LIMITS_ENFORCED,
            SubmissionAcceptanceRequirement.ORIGINAL_FILENAME_DISCARDED,
            SubmissionAcceptanceRequirement.MEDIA_DECLARATIONS_DISTRUSTED,
            SubmissionAcceptanceRequirement.SANDBOX_DECISION_READY,
        ),
    ),
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=3,
        phase=SubmissionAcceptancePhase.OBTAIN_PRE_ACTION_AUDIT_EVIDENCE,
        checkpoint=(
            SubmissionAcceptanceCheckpoint.
            REQUESTED_RECEIPT_DURABLE_BEFORE_KEY_OR_CONTENT
        ),
        requirements=(
            SubmissionAcceptanceRequirement.REQUESTED_RECEIPT_DURABLE,
            SubmissionAcceptanceRequirement.REQUESTED_RECEIPT_CONTEXT_VALID,
        ),
    ),
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=4,
        phase=SubmissionAcceptancePhase.PROTECT_AND_STAGE,
        checkpoint=(
            SubmissionAcceptanceCheckpoint.
            CIPHERTEXT_AND_METADATA_STAGED_NON_VISIBLE
        ),
        requirements=(
            (
                SubmissionAcceptanceRequirement.
                NEW_REPORT_PROTECTION_CAPABILITY_READY
            ),
            SubmissionAcceptanceRequirement.CIPHERTEXT_OBJECTS_DURABLY_VERIFIED,
            SubmissionAcceptanceRequirement.METADATA_STAGED_NON_VISIBLE,
        ),
    ),
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=5,
        phase=SubmissionAcceptancePhase.AUDIT_AND_COMMIT_ACCEPTANCE,
        checkpoint=(
            SubmissionAcceptanceCheckpoint.
            RECEIVED_RECEIPT_BOUND_TO_SEALED_COMMIT
        ),
        requirements=(
            SubmissionAcceptanceRequirement.RECEIVED_RECEIPT_DURABLE,
            SubmissionAcceptanceRequirement.RECEIVED_RECEIPT_CONTEXT_VALID,
            SubmissionAcceptanceRequirement.STATE_VERSION_RELOCKED,
            SubmissionAcceptanceRequirement.SEALED_COMMIT_READY,
        ),
    ),
    SubmissionAcceptanceCheckpointDescriptorV1(
        sequence_index=6,
        phase=SubmissionAcceptancePhase.RECONCILE_WITHOUT_PLAINTEXT,
        checkpoint=(
            SubmissionAcceptanceCheckpoint.NONTERMINAL_ATTEMPT_FINISHED_OR_ABORTED
        ),
        requirements=(
            (
                SubmissionAcceptanceRequirement.
                NONTERMINAL_ATTEMPT_SELECTED_BY_STATE_AND_TIME
            ),
            SubmissionAcceptanceRequirement.EVIDENCED_FINISH_OR_SCOPED_ABORT_ONLY,
        ),
    ),
)


def validate_submission_acceptance_checkpoint_descriptor_v1(
    descriptor: SubmissionAcceptanceCheckpointDescriptorV1,
) -> SubmissionAcceptanceCheckpointDescriptorV1:
    return _require_checkpoint_descriptor(descriptor)


def validate_submission_acceptance_checkpoint_profile_v1(
    profile: SubmissionAcceptanceCheckpointProfileV1,
) -> StructurallyValidSubmissionAcceptanceCheckpointProfileV1:
    if type(profile) is not SubmissionAcceptanceCheckpointProfileV1:
        _reject()
    normalized = SubmissionAcceptanceCheckpointProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION,
        ),
        checkpoints=_require_checkpoint_sequence(profile.checkpoints),
        forbidden_capabilities=_require_forbidden_capabilities(
            profile.forbidden_capabilities
        ),
    )
    expected = expected_submission_acceptance_checkpoint_profile_v1()
    if normalized != expected:
        _reject()
    return StructurallyValidSubmissionAcceptanceCheckpointProfileV1(normalized)


def expected_submission_acceptance_checkpoint_profile_v1(
) -> SubmissionAcceptanceCheckpointProfileV1:
    return SubmissionAcceptanceCheckpointProfileV1(
        scheme_version=SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION,
        checkpoints=SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1,
        forbidden_capabilities=(
            SUBMISSION_ACCEPTANCE_FORBIDDEN_CAPABILITIES_V1
        ),
    )
