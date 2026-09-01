"""Inert credential-response descriptors from the approved docs/20 flow.

This module validates only static lost-response and one-time-display policy
metadata. It does not generate credentials, persist secrets, render responses,
inspect requests, mutate submission attempts, call services, or authorize
recovery/submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SubmissionCredentialResponseDescriptorRejected


SUBMISSION_CREDENTIAL_RESPONSE_PROFILE_VERSION = 1


class SubmissionCredentialResponseOpportunity(StrEnum):
    ONE_LIVE_POST_ACCEPTANCE_RESPONSE = "ONE_LIVE_POST_ACCEPTANCE_RESPONSE"


class SubmissionCredentialResponseRetryResult(StrEnum):
    CONTROLLED_INDETERMINATE_OUTCOME = "CONTROLLED_INDETERMINATE_OUTCOME"


class SubmissionCredentialResponsePermittedField(StrEnum):
    TICKET_ID = "TICKET_ID"
    RECOVERY_SECRET = "RECOVERY_SECRET"


class SubmissionCredentialResponseForbiddenPersistence(StrEnum):
    PLAINTEXT_RECOVERY_SECRET = "PLAINTEXT_RECOVERY_SECRET"
    CREDENTIAL_REDISPLAY_STATE = "CREDENTIAL_REDISPLAY_STATE"
    REPLACEMENT_CREDENTIAL_STATE = "REPLACEMENT_CREDENTIAL_STATE"
    CREDENTIALS_DELIVERED_CLAIM = "CREDENTIALS_DELIVERED_CLAIM"
    CONTENT_HASH_OR_DEDUPLICATION = "CONTENT_HASH_OR_DEDUPLICATION"
    REQUEST_HEADER = "REQUEST_HEADER"
    RAW_ERROR = "RAW_ERROR"


SUBMISSION_CREDENTIAL_RESPONSE_PERMITTED_FIELDS_V1 = (
    SubmissionCredentialResponsePermittedField.TICKET_ID,
    SubmissionCredentialResponsePermittedField.RECOVERY_SECRET,
)

SUBMISSION_CREDENTIAL_RESPONSE_FORBIDDEN_PERSISTENCE_V1 = (
    SubmissionCredentialResponseForbiddenPersistence.PLAINTEXT_RECOVERY_SECRET,
    SubmissionCredentialResponseForbiddenPersistence.CREDENTIAL_REDISPLAY_STATE,
    SubmissionCredentialResponseForbiddenPersistence.REPLACEMENT_CREDENTIAL_STATE,
    SubmissionCredentialResponseForbiddenPersistence.CREDENTIALS_DELIVERED_CLAIM,
    SubmissionCredentialResponseForbiddenPersistence.CONTENT_HASH_OR_DEDUPLICATION,
    SubmissionCredentialResponseForbiddenPersistence.REQUEST_HEADER,
    SubmissionCredentialResponseForbiddenPersistence.RAW_ERROR,
)


@dataclass(frozen=True, slots=True)
class SubmissionCredentialResponsePolicyV1:
    opportunity: SubmissionCredentialResponseOpportunity
    retry_result: SubmissionCredentialResponseRetryResult
    permitted_fields: tuple[SubmissionCredentialResponsePermittedField, ...]
    forbidden_persistence: tuple[
        SubmissionCredentialResponseForbiddenPersistence,
        ...,
    ]


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionCredentialResponsePolicyV1:
    policy: SubmissionCredentialResponsePolicyV1

    @property
    def generates_credentials(self) -> bool:
        return False

    @property
    def persists_recovery_secret(self) -> bool:
        return False

    @property
    def redisplays_recovery_secret(self) -> bool:
        return False

    @property
    def issues_replacement_credentials(self) -> bool:
        return False

    @property
    def records_credentials_delivered(self) -> bool:
        return False

    @property
    def deduplicates_by_content(self) -> bool:
        return False

    @property
    def creates_duplicate_report(self) -> bool:
        return False

    @property
    def renders_response(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionCredentialResponseDescriptorRejected()


def _require_opportunity(
    value: object,
) -> SubmissionCredentialResponseOpportunity:
    if isinstance(value, SubmissionCredentialResponseOpportunity):
        return value
    _reject()


def _require_retry_result(
    value: object,
) -> SubmissionCredentialResponseRetryResult:
    if isinstance(value, SubmissionCredentialResponseRetryResult):
        return value
    _reject()


def _require_permitted_field(
    value: object,
) -> SubmissionCredentialResponsePermittedField:
    if isinstance(value, SubmissionCredentialResponsePermittedField):
        return value
    _reject()


def _require_forbidden_persistence(
    value: object,
) -> SubmissionCredentialResponseForbiddenPersistence:
    if isinstance(value, SubmissionCredentialResponseForbiddenPersistence):
        return value
    _reject()


def _require_permitted_fields(
    value: object,
) -> tuple[SubmissionCredentialResponsePermittedField, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_permitted_field(item) for item in value)
    if normalized != SUBMISSION_CREDENTIAL_RESPONSE_PERMITTED_FIELDS_V1:
        _reject()
    return normalized


def _require_forbidden_persistence_fields(
    value: object,
) -> tuple[SubmissionCredentialResponseForbiddenPersistence, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_persistence(item) for item in value)
    if normalized != SUBMISSION_CREDENTIAL_RESPONSE_FORBIDDEN_PERSISTENCE_V1:
        _reject()
    return normalized


def validate_submission_credential_response_policy_v1(
    policy: SubmissionCredentialResponsePolicyV1,
) -> StructurallyValidSubmissionCredentialResponsePolicyV1:
    if type(policy) is not SubmissionCredentialResponsePolicyV1:
        _reject()
    normalized = SubmissionCredentialResponsePolicyV1(
        opportunity=_require_opportunity(policy.opportunity),
        retry_result=_require_retry_result(policy.retry_result),
        permitted_fields=_require_permitted_fields(policy.permitted_fields),
        forbidden_persistence=_require_forbidden_persistence_fields(
            policy.forbidden_persistence
        ),
    )
    if normalized != expected_submission_credential_response_policy_v1():
        _reject()
    return StructurallyValidSubmissionCredentialResponsePolicyV1(
        policy=normalized
    )


def expected_submission_credential_response_policy_v1(
) -> SubmissionCredentialResponsePolicyV1:
    """Return only the approved one-time credential response policy metadata."""

    return SubmissionCredentialResponsePolicyV1(
        opportunity=(
            SubmissionCredentialResponseOpportunity.
            ONE_LIVE_POST_ACCEPTANCE_RESPONSE
        ),
        retry_result=(
            SubmissionCredentialResponseRetryResult.
            CONTROLLED_INDETERMINATE_OUTCOME
        ),
        permitted_fields=SUBMISSION_CREDENTIAL_RESPONSE_PERMITTED_FIELDS_V1,
        forbidden_persistence=(
            SUBMISSION_CREDENTIAL_RESPONSE_FORBIDDEN_PERSISTENCE_V1
        ),
    )
