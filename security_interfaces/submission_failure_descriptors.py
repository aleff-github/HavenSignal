"""Inert submission failure-matrix descriptors from docs/20.

This module validates only static failure-boundary and required-result
metadata for the approved submission acceptance protocol. It does not handle
requests, start submission pipelines, call services, write storage, create
keys, persist plaintext, append audit events, mutate state, return
credentials, expose endpoints, or authorize submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SubmissionFailureDescriptorRejected


SUBMISSION_FAILURE_PROFILE_VERSION = 1


class SubmissionFailureBoundary(StrEnum):
    UNSUPPORTED_METHOD_FRAMING_SIZE_CSRF_CAPTCHA_OR_ATTEMPT = (
        "UNSUPPORTED_METHOD_FRAMING_SIZE_CSRF_CAPTCHA_OR_ATTEMPT"
    )
    PARALLEL_REQUESTS_FOR_ONE_ATTEMPT = "PARALLEL_REQUESTS_FOR_ONE_ATTEMPT"
    AUDIT_REQUESTED_UNAVAILABLE = "AUDIT_REQUESTED_UNAVAILABLE"
    VALIDATION_OR_SANDBOX_UNCERTAINTY = "VALIDATION_OR_SANDBOX_UNCERTAINTY"
    KEY_SERVICE_UNAVAILABLE = "KEY_SERVICE_UNAVAILABLE"
    ENCRYPTION_OR_STAGING_FAILURE = "ENCRYPTION_OR_STAGING_FAILURE"
    METADATA_TRANSACTION_FAILURE = "METADATA_TRANSACTION_FAILURE"
    SUBMISSION_RECEIVED_AUDIT_UNAVAILABLE = (
        "SUBMISSION_RECEIVED_AUDIT_UNAVAILABLE"
    )
    CRASH_AFTER_FINAL_RECEIPT_BEFORE_SEALED = (
        "CRASH_AFTER_FINAL_RECEIPT_BEFORE_SEALED"
    )
    CRASH_AFTER_SEALED_BEFORE_OR_DURING_RESPONSE = (
        "CRASH_AFTER_SEALED_BEFORE_OR_DURING_RESPONSE"
    )
    DUPLICATE_OR_STALE_RETRY_AFTER_ACCEPTANCE = (
        "DUPLICATE_OR_STALE_RETRY_AFTER_ACCEPTANCE"
    )
    KEY_OR_CIPHERTEXT_CLEANUP_FAILURE = "KEY_OR_CIPHERTEXT_CLEANUP_FAILURE"
    UNKNOWN_STATE_VERSION_OR_RECEIPT = "UNKNOWN_STATE_VERSION_OR_RECEIPT"


class SubmissionFailureRequiredResult(StrEnum):
    REJECT_BEFORE_ACCEPTANCE_NO_FALLBACK_OR_THIRD_PARTY_CHALLENGE = (
        "REJECT_BEFORE_ACCEPTANCE_NO_FALLBACK_OR_THIRD_PARTY_CHALLENGE"
    )
    ONE_DATABASE_WINNER_LOSERS_NO_PIPELINE = (
        "ONE_DATABASE_WINNER_LOSERS_NO_PIPELINE"
    )
    NO_KEY_OR_DURABLE_REPORT_CONTENT_CREATED = (
        "NO_KEY_OR_DURABLE_REPORT_CONTENT_CREATED"
    )
    REJECT_NO_WEAKER_PARSER_OR_IN_PROCESS_FALLBACK = (
        "REJECT_NO_WEAKER_PARSER_OR_IN_PROCESS_FALLBACK"
    )
    NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS = (
        "NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS"
    )
    NON_VISIBLE_DESTROY_SCOPED_KEY_AND_STAGED_OBJECTS = (
        "NON_VISIBLE_DESTROY_SCOPED_KEY_AND_STAGED_OBJECTS"
    )
    NO_SEALED_RECONCILE_OR_DESTROY_STAGED_MATERIAL = (
        "NO_SEALED_RECONCILE_OR_DESTROY_STAGED_MATERIAL"
    )
    NON_VISIBLE_STAGING_APPROVED_RECONCILIATION_NO_CREDENTIALS = (
        "NON_VISIBLE_STAGING_APPROVED_RECONCILIATION_NO_CREDENTIALS"
    )
    RECONCILER_FINISH_ONLY_WITH_EXACT_BINDINGS = (
        "RECONCILER_FINISH_ONLY_WITH_EXACT_BINDINGS"
    )
    ONE_ACCEPTED_REPORT_NO_REISSUE_NO_DUPLICATE = (
        "ONE_ACCEPTED_REPORT_NO_REISSUE_NO_DUPLICATE"
    )
    CONTROLLED_INDETERMINATE_NO_STATUS_ORACLE_NO_REDISPLAY = (
        "CONTROLLED_INDETERMINATE_NO_STATUS_ORACLE_NO_REDISPLAY"
    )
    INACCESSIBLE_RETRY_AND_ALERT_APPROVED_POLICY = (
        "INACCESSIBLE_RETRY_AND_ALERT_APPROVED_POLICY"
    )
    FAIL_CLOSED_SECURITY_REVIEW_NO_GUESSED_TRANSITION = (
        "FAIL_CLOSED_SECURITY_REVIEW_NO_GUESSED_TRANSITION"
    )


SUBMISSION_FAILURE_BOUNDARIES_V1 = (
    SubmissionFailureBoundary.UNSUPPORTED_METHOD_FRAMING_SIZE_CSRF_CAPTCHA_OR_ATTEMPT,
    SubmissionFailureBoundary.PARALLEL_REQUESTS_FOR_ONE_ATTEMPT,
    SubmissionFailureBoundary.AUDIT_REQUESTED_UNAVAILABLE,
    SubmissionFailureBoundary.VALIDATION_OR_SANDBOX_UNCERTAINTY,
    SubmissionFailureBoundary.KEY_SERVICE_UNAVAILABLE,
    SubmissionFailureBoundary.ENCRYPTION_OR_STAGING_FAILURE,
    SubmissionFailureBoundary.METADATA_TRANSACTION_FAILURE,
    SubmissionFailureBoundary.SUBMISSION_RECEIVED_AUDIT_UNAVAILABLE,
    SubmissionFailureBoundary.CRASH_AFTER_FINAL_RECEIPT_BEFORE_SEALED,
    SubmissionFailureBoundary.CRASH_AFTER_SEALED_BEFORE_OR_DURING_RESPONSE,
    SubmissionFailureBoundary.DUPLICATE_OR_STALE_RETRY_AFTER_ACCEPTANCE,
    SubmissionFailureBoundary.KEY_OR_CIPHERTEXT_CLEANUP_FAILURE,
    SubmissionFailureBoundary.UNKNOWN_STATE_VERSION_OR_RECEIPT,
)

SUBMISSION_FAILURE_REQUIRED_RESULTS_V1 = (
    (
        SubmissionFailureRequiredResult.
        REJECT_BEFORE_ACCEPTANCE_NO_FALLBACK_OR_THIRD_PARTY_CHALLENGE
    ),
    SubmissionFailureRequiredResult.ONE_DATABASE_WINNER_LOSERS_NO_PIPELINE,
    SubmissionFailureRequiredResult.NO_KEY_OR_DURABLE_REPORT_CONTENT_CREATED,
    (
        SubmissionFailureRequiredResult.
        REJECT_NO_WEAKER_PARSER_OR_IN_PROCESS_FALLBACK
    ),
    SubmissionFailureRequiredResult.NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS,
    (
        SubmissionFailureRequiredResult.
        NON_VISIBLE_DESTROY_SCOPED_KEY_AND_STAGED_OBJECTS
    ),
    SubmissionFailureRequiredResult.NO_SEALED_RECONCILE_OR_DESTROY_STAGED_MATERIAL,
    (
        SubmissionFailureRequiredResult.
        NON_VISIBLE_STAGING_APPROVED_RECONCILIATION_NO_CREDENTIALS
    ),
    SubmissionFailureRequiredResult.RECONCILER_FINISH_ONLY_WITH_EXACT_BINDINGS,
    SubmissionFailureRequiredResult.ONE_ACCEPTED_REPORT_NO_REISSUE_NO_DUPLICATE,
    (
        SubmissionFailureRequiredResult.
        CONTROLLED_INDETERMINATE_NO_STATUS_ORACLE_NO_REDISPLAY
    ),
    SubmissionFailureRequiredResult.INACCESSIBLE_RETRY_AND_ALERT_APPROVED_POLICY,
    (
        SubmissionFailureRequiredResult.
        FAIL_CLOSED_SECURITY_REVIEW_NO_GUESSED_TRANSITION
    ),
)


@dataclass(frozen=True, slots=True)
class SubmissionFailureCaseV1:
    boundary: SubmissionFailureBoundary
    required_result: SubmissionFailureRequiredResult
    content_free: bool
    fail_closed: bool


@dataclass(frozen=True, slots=True)
class SubmissionFailureProfileV1:
    scheme_version: int
    cases: tuple[SubmissionFailureCaseV1, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionFailureProfileV1:
    profile: SubmissionFailureProfileV1

    @property
    def handles_request(self) -> bool:
        return False

    @property
    def starts_pipeline(self) -> bool:
        return False

    @property
    def calls_service(self) -> bool:
        return False

    @property
    def writes_storage(self) -> bool:
        return False

    @property
    def creates_key(self) -> bool:
        return False

    @property
    def persists_plaintext(self) -> bool:
        return False

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def mutates_state(self) -> bool:
        return False

    @property
    def returns_credentials(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionFailureDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_true(value: object) -> bool:
    if value is not True:
        _reject()
    return True


def _require_boundary(value: object) -> SubmissionFailureBoundary:
    if isinstance(value, SubmissionFailureBoundary):
        return value
    _reject()


def _require_required_result(
    value: object,
) -> SubmissionFailureRequiredResult:
    if isinstance(value, SubmissionFailureRequiredResult):
        return value
    _reject()


def _require_failure_case(value: object) -> SubmissionFailureCaseV1:
    if type(value) is not SubmissionFailureCaseV1:
        _reject()
    normalized = SubmissionFailureCaseV1(
        boundary=_require_boundary(value.boundary),
        required_result=_require_required_result(value.required_result),
        content_free=_require_true(value.content_free),
        fail_closed=_require_true(value.fail_closed),
    )
    try:
        expected_index = SUBMISSION_FAILURE_BOUNDARIES_V1.index(
            normalized.boundary
        )
    except ValueError:
        _reject()
    expected = SubmissionFailureCaseV1(
        boundary=SUBMISSION_FAILURE_BOUNDARIES_V1[expected_index],
        required_result=SUBMISSION_FAILURE_REQUIRED_RESULTS_V1[expected_index],
        content_free=True,
        fail_closed=True,
    )
    if normalized != expected:
        _reject()
    return normalized


def _require_failure_cases(
    value: object,
) -> tuple[SubmissionFailureCaseV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_failure_case(item) for item in value)
    if normalized != SUBMISSION_FAILURE_CASES_V1:
        _reject()
    return normalized


SUBMISSION_FAILURE_CASES_V1 = tuple(
    SubmissionFailureCaseV1(
        boundary=boundary,
        required_result=required_result,
        content_free=True,
        fail_closed=True,
    )
    for boundary, required_result in zip(
        SUBMISSION_FAILURE_BOUNDARIES_V1,
        SUBMISSION_FAILURE_REQUIRED_RESULTS_V1,
        strict=True,
    )
)


def validate_submission_failure_case_v1(
    failure_case: SubmissionFailureCaseV1,
) -> SubmissionFailureCaseV1:
    return _require_failure_case(failure_case)


def validate_submission_failure_profile_v1(
    profile: SubmissionFailureProfileV1,
) -> StructurallyValidSubmissionFailureProfileV1:
    if type(profile) is not SubmissionFailureProfileV1:
        _reject()
    normalized = SubmissionFailureProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_FAILURE_PROFILE_VERSION,
        ),
        cases=_require_failure_cases(profile.cases),
    )
    expected = expected_submission_failure_profile_v1()
    if normalized != expected:
        _reject()
    return StructurallyValidSubmissionFailureProfileV1(normalized)


def expected_submission_failure_profile_v1() -> SubmissionFailureProfileV1:
    return SubmissionFailureProfileV1(
        scheme_version=SUBMISSION_FAILURE_PROFILE_VERSION,
        cases=SUBMISSION_FAILURE_CASES_V1,
    )
