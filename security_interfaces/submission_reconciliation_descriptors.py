"""Inert submission-reconciliation descriptors from the approved docs/20 flow.

This module validates only static timing, action, state, alert, and payload
metadata for future crash reconciliation. It does not scan report content,
decrypt plaintext, create credentials, call services, mutate attempts, delete
objects, schedule jobs, or authorize submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .alert_descriptors import AlertType
from .errors import SubmissionReconciliationDescriptorRejected


SUBMISSION_RECONCILIATION_PROFILE_VERSION = 1
SUBMISSION_RECONCILIATION_SCAN_INTERVAL_MAX_MS = 60 * 1000
SUBMISSION_RECONCILIATION_PROGRESS_DEADLINE_MS = 15 * 60 * 1000
SUBMISSION_RECONCILIATION_CLEANUP_RETRY_INTERVAL_MAX_MS = 5 * 60 * 1000
SUBMISSION_RECONCILIATION_CLEANUP_ALERT_AFTER_MS = 15 * 60 * 1000


class SubmissionReconciliationCandidateState(StrEnum):
    READY = "READY"
    PROCESSING = "PROCESSING"
    CIPHERTEXT_STAGED = "CIPHERTEXT_STAGED"
    AUDIT_CONFIRMED = "AUDIT_CONFIRMED"
    ABORTING = "ABORTING"


class SubmissionReconciliationTerminalOutcome(StrEnum):
    ACCEPTED_WITH_CREDENTIAL_RESPONSE_UNAVAILABLE = (
        "ACCEPTED_WITH_CREDENTIAL_RESPONSE_UNAVAILABLE"
    )
    ABORTED_AFTER_SCOPED_CLEANUP = "ABORTED_AFTER_SCOPED_CLEANUP"


class SubmissionReconciliationAction(StrEnum):
    SCAN_NONTERMINAL_ATTEMPTS = "SCAN_NONTERMINAL_ATTEMPTS"
    COMPLETE_EVIDENCED_ACCEPTANCE = "COMPLETE_EVIDENCED_ACCEPTANCE"
    ENTER_ABORTING = "ENTER_ABORTING"
    DESTROY_SCOPED_REPORT_KEY = "DESTROY_SCOPED_REPORT_KEY"
    RETRY_SCOPED_CIPHERTEXT_METADATA_DELETION = (
        "RETRY_SCOPED_CIPHERTEXT_METADATA_DELETION"
    )
    END_ABORTED = "END_ABORTED"
    REQUEST_CIPHERTEXT_DELETE_PERSISTENT_FAILURE_ALERT = (
        "REQUEST_CIPHERTEXT_DELETE_PERSISTENT_FAILURE_ALERT"
    )


class SubmissionReconciliationAllowedPayloadField(StrEnum):
    SYSTEM_GENERATED_ATTEMPT_IDENTIFIER = "SYSTEM_GENERATED_ATTEMPT_IDENTIFIER"
    ATTEMPT_STATE = "ATTEMPT_STATE"
    ATTEMPT_VERSION = "ATTEMPT_VERSION"
    SERVER_TIME = "SERVER_TIME"
    IDEMPOTENCY_CONTEXT = "IDEMPOTENCY_CONTEXT"
    SCOPED_CLEANUP_IDENTIFIER = "SCOPED_CLEANUP_IDENTIFIER"
    CONTROLLED_CONDITION_CODE = "CONTROLLED_CONDITION_CODE"


class SubmissionReconciliationForbiddenPayloadField(StrEnum):
    REPORT_TEXT = "REPORT_TEXT"
    ATTACHMENT_CONTENT = "ATTACHMENT_CONTENT"
    ORIGINAL_FILENAME = "ORIGINAL_FILENAME"
    RECOVERY_SECRET = "RECOVERY_SECRET"
    CREDENTIAL_RESPONSE = "CREDENTIAL_RESPONSE"
    CRYPTOGRAPHIC_KEY = "CRYPTOGRAPHIC_KEY"
    CIPHERTEXT_BYTES = "CIPHERTEXT_BYTES"
    AUDIT_RECEIPT_BYTES = "AUDIT_RECEIPT_BYTES"
    REQUEST_HEADER = "REQUEST_HEADER"
    RAW_ERROR = "RAW_ERROR"


SUBMISSION_RECONCILIATION_CANDIDATE_STATES_V1 = (
    SubmissionReconciliationCandidateState.READY,
    SubmissionReconciliationCandidateState.PROCESSING,
    SubmissionReconciliationCandidateState.CIPHERTEXT_STAGED,
    SubmissionReconciliationCandidateState.AUDIT_CONFIRMED,
    SubmissionReconciliationCandidateState.ABORTING,
)

SUBMISSION_RECONCILIATION_TERMINAL_OUTCOMES_V1 = (
    (
        SubmissionReconciliationTerminalOutcome.
        ACCEPTED_WITH_CREDENTIAL_RESPONSE_UNAVAILABLE
    ),
    SubmissionReconciliationTerminalOutcome.ABORTED_AFTER_SCOPED_CLEANUP,
)

SUBMISSION_RECONCILIATION_ACTIONS_V1 = (
    SubmissionReconciliationAction.SCAN_NONTERMINAL_ATTEMPTS,
    SubmissionReconciliationAction.COMPLETE_EVIDENCED_ACCEPTANCE,
    SubmissionReconciliationAction.ENTER_ABORTING,
    SubmissionReconciliationAction.DESTROY_SCOPED_REPORT_KEY,
    SubmissionReconciliationAction.RETRY_SCOPED_CIPHERTEXT_METADATA_DELETION,
    SubmissionReconciliationAction.END_ABORTED,
    (
        SubmissionReconciliationAction.
        REQUEST_CIPHERTEXT_DELETE_PERSISTENT_FAILURE_ALERT
    ),
)

SUBMISSION_RECONCILIATION_ALLOWED_PAYLOAD_FIELDS_V1 = (
    (
        SubmissionReconciliationAllowedPayloadField.
        SYSTEM_GENERATED_ATTEMPT_IDENTIFIER
    ),
    SubmissionReconciliationAllowedPayloadField.ATTEMPT_STATE,
    SubmissionReconciliationAllowedPayloadField.ATTEMPT_VERSION,
    SubmissionReconciliationAllowedPayloadField.SERVER_TIME,
    SubmissionReconciliationAllowedPayloadField.IDEMPOTENCY_CONTEXT,
    SubmissionReconciliationAllowedPayloadField.SCOPED_CLEANUP_IDENTIFIER,
    SubmissionReconciliationAllowedPayloadField.CONTROLLED_CONDITION_CODE,
)

SUBMISSION_RECONCILIATION_FORBIDDEN_PAYLOAD_FIELDS_V1 = (
    SubmissionReconciliationForbiddenPayloadField.REPORT_TEXT,
    SubmissionReconciliationForbiddenPayloadField.ATTACHMENT_CONTENT,
    SubmissionReconciliationForbiddenPayloadField.ORIGINAL_FILENAME,
    SubmissionReconciliationForbiddenPayloadField.RECOVERY_SECRET,
    SubmissionReconciliationForbiddenPayloadField.CREDENTIAL_RESPONSE,
    SubmissionReconciliationForbiddenPayloadField.CRYPTOGRAPHIC_KEY,
    SubmissionReconciliationForbiddenPayloadField.CIPHERTEXT_BYTES,
    SubmissionReconciliationForbiddenPayloadField.AUDIT_RECEIPT_BYTES,
    SubmissionReconciliationForbiddenPayloadField.REQUEST_HEADER,
    SubmissionReconciliationForbiddenPayloadField.RAW_ERROR,
)


@dataclass(frozen=True, slots=True)
class SubmissionReconciliationTimingProfileV1:
    scan_interval_max_ms: int
    progress_deadline_ms: int
    cleanup_retry_interval_max_ms: int
    cleanup_alert_after_ms: int


@dataclass(frozen=True, slots=True)
class SubmissionReconciliationStateProfileV1:
    candidate_states: tuple[SubmissionReconciliationCandidateState, ...]
    terminal_outcomes: tuple[SubmissionReconciliationTerminalOutcome, ...]


@dataclass(frozen=True, slots=True)
class SubmissionReconciliationActionProfileV1:
    actions: tuple[SubmissionReconciliationAction, ...]
    persistent_cleanup_alert_type: AlertType


@dataclass(frozen=True, slots=True)
class SubmissionReconciliationPayloadPolicyV1:
    allowed_fields: tuple[SubmissionReconciliationAllowedPayloadField, ...]
    forbidden_fields: tuple[SubmissionReconciliationForbiddenPayloadField, ...]


@dataclass(frozen=True, slots=True)
class SubmissionReconciliationProfileV1:
    scheme_version: int
    timing: SubmissionReconciliationTimingProfileV1
    states: SubmissionReconciliationStateProfileV1
    actions: SubmissionReconciliationActionProfileV1
    payload_policy: SubmissionReconciliationPayloadPolicyV1


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionReconciliationProfileV1:
    profile: SubmissionReconciliationProfileV1

    @property
    def scans_report_content(self) -> bool:
        return False

    @property
    def decrypts_plaintext(self) -> bool:
        return False

    @property
    def creates_credentials(self) -> bool:
        return False

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def verifies_audit_receipt(self) -> bool:
        return False

    @property
    def calls_audit_service(self) -> bool:
        return False

    @property
    def calls_key_service(self) -> bool:
        return False

    @property
    def calls_alert_service(self) -> bool:
        return False

    @property
    def deletes_ciphertext(self) -> bool:
        return False

    @property
    def mutates_attempt_state(self) -> bool:
        return False

    @property
    def schedules_job(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionReconciliationDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_candidate_state(
    value: object,
) -> SubmissionReconciliationCandidateState:
    if isinstance(value, SubmissionReconciliationCandidateState):
        return value
    _reject()


def _require_terminal_outcome(
    value: object,
) -> SubmissionReconciliationTerminalOutcome:
    if isinstance(value, SubmissionReconciliationTerminalOutcome):
        return value
    _reject()


def _require_action(value: object) -> SubmissionReconciliationAction:
    if isinstance(value, SubmissionReconciliationAction):
        return value
    _reject()


def _require_alert_type(value: object) -> AlertType:
    if isinstance(value, AlertType):
        return value
    _reject()


def _require_allowed_payload_field(
    value: object,
) -> SubmissionReconciliationAllowedPayloadField:
    if isinstance(value, SubmissionReconciliationAllowedPayloadField):
        return value
    _reject()


def _require_forbidden_payload_field(
    value: object,
) -> SubmissionReconciliationForbiddenPayloadField:
    if isinstance(value, SubmissionReconciliationForbiddenPayloadField):
        return value
    _reject()


def _require_candidate_states(
    value: object,
) -> tuple[SubmissionReconciliationCandidateState, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_candidate_state(item) for item in value)
    if normalized != SUBMISSION_RECONCILIATION_CANDIDATE_STATES_V1:
        _reject()
    return normalized


def _require_terminal_outcomes(
    value: object,
) -> tuple[SubmissionReconciliationTerminalOutcome, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_terminal_outcome(item) for item in value)
    if normalized != SUBMISSION_RECONCILIATION_TERMINAL_OUTCOMES_V1:
        _reject()
    return normalized


def _require_actions(
    value: object,
) -> tuple[SubmissionReconciliationAction, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_action(item) for item in value)
    if normalized != SUBMISSION_RECONCILIATION_ACTIONS_V1:
        _reject()
    return normalized


def _require_allowed_payload_fields(
    value: object,
) -> tuple[SubmissionReconciliationAllowedPayloadField, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_allowed_payload_field(item) for item in value)
    if normalized != SUBMISSION_RECONCILIATION_ALLOWED_PAYLOAD_FIELDS_V1:
        _reject()
    return normalized


def _require_forbidden_payload_fields(
    value: object,
) -> tuple[SubmissionReconciliationForbiddenPayloadField, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_payload_field(item) for item in value)
    if normalized != SUBMISSION_RECONCILIATION_FORBIDDEN_PAYLOAD_FIELDS_V1:
        _reject()
    return normalized


def validate_submission_reconciliation_timing_profile_v1(
    timing: SubmissionReconciliationTimingProfileV1,
) -> SubmissionReconciliationTimingProfileV1:
    if type(timing) is not SubmissionReconciliationTimingProfileV1:
        _reject()
    return SubmissionReconciliationTimingProfileV1(
        scan_interval_max_ms=_require_uint_exact(
            timing.scan_interval_max_ms,
            expected=SUBMISSION_RECONCILIATION_SCAN_INTERVAL_MAX_MS,
        ),
        progress_deadline_ms=_require_uint_exact(
            timing.progress_deadline_ms,
            expected=SUBMISSION_RECONCILIATION_PROGRESS_DEADLINE_MS,
        ),
        cleanup_retry_interval_max_ms=_require_uint_exact(
            timing.cleanup_retry_interval_max_ms,
            expected=SUBMISSION_RECONCILIATION_CLEANUP_RETRY_INTERVAL_MAX_MS,
        ),
        cleanup_alert_after_ms=_require_uint_exact(
            timing.cleanup_alert_after_ms,
            expected=SUBMISSION_RECONCILIATION_CLEANUP_ALERT_AFTER_MS,
        ),
    )


def validate_submission_reconciliation_state_profile_v1(
    states: SubmissionReconciliationStateProfileV1,
) -> SubmissionReconciliationStateProfileV1:
    if type(states) is not SubmissionReconciliationStateProfileV1:
        _reject()
    return SubmissionReconciliationStateProfileV1(
        candidate_states=_require_candidate_states(states.candidate_states),
        terminal_outcomes=_require_terminal_outcomes(
            states.terminal_outcomes
        ),
    )


def validate_submission_reconciliation_action_profile_v1(
    actions: SubmissionReconciliationActionProfileV1,
) -> SubmissionReconciliationActionProfileV1:
    if type(actions) is not SubmissionReconciliationActionProfileV1:
        _reject()
    alert_type = _require_alert_type(actions.persistent_cleanup_alert_type)
    if alert_type is not AlertType.CIPHERTEXT_DELETE_PERSISTENT_FAILURE:
        _reject()
    return SubmissionReconciliationActionProfileV1(
        actions=_require_actions(actions.actions),
        persistent_cleanup_alert_type=alert_type,
    )


def validate_submission_reconciliation_payload_policy_v1(
    policy: SubmissionReconciliationPayloadPolicyV1,
) -> SubmissionReconciliationPayloadPolicyV1:
    if type(policy) is not SubmissionReconciliationPayloadPolicyV1:
        _reject()
    return SubmissionReconciliationPayloadPolicyV1(
        allowed_fields=_require_allowed_payload_fields(policy.allowed_fields),
        forbidden_fields=_require_forbidden_payload_fields(
            policy.forbidden_fields
        ),
    )


def validate_submission_reconciliation_profile_v1(
    profile: SubmissionReconciliationProfileV1,
) -> StructurallyValidSubmissionReconciliationProfileV1:
    if type(profile) is not SubmissionReconciliationProfileV1:
        _reject()
    normalized = SubmissionReconciliationProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_RECONCILIATION_PROFILE_VERSION,
        ),
        timing=validate_submission_reconciliation_timing_profile_v1(
            profile.timing
        ),
        states=validate_submission_reconciliation_state_profile_v1(
            profile.states
        ),
        actions=validate_submission_reconciliation_action_profile_v1(
            profile.actions
        ),
        payload_policy=validate_submission_reconciliation_payload_policy_v1(
            profile.payload_policy
        ),
    )
    return StructurallyValidSubmissionReconciliationProfileV1(
        profile=normalized
    )


def expected_submission_reconciliation_profile_v1(
) -> SubmissionReconciliationProfileV1:
    """Return only the approved reconciliation timing/action metadata."""

    return SubmissionReconciliationProfileV1(
        scheme_version=SUBMISSION_RECONCILIATION_PROFILE_VERSION,
        timing=SubmissionReconciliationTimingProfileV1(
            scan_interval_max_ms=(
                SUBMISSION_RECONCILIATION_SCAN_INTERVAL_MAX_MS
            ),
            progress_deadline_ms=(
                SUBMISSION_RECONCILIATION_PROGRESS_DEADLINE_MS
            ),
            cleanup_retry_interval_max_ms=(
                SUBMISSION_RECONCILIATION_CLEANUP_RETRY_INTERVAL_MAX_MS
            ),
            cleanup_alert_after_ms=(
                SUBMISSION_RECONCILIATION_CLEANUP_ALERT_AFTER_MS
            ),
        ),
        states=SubmissionReconciliationStateProfileV1(
            candidate_states=SUBMISSION_RECONCILIATION_CANDIDATE_STATES_V1,
            terminal_outcomes=SUBMISSION_RECONCILIATION_TERMINAL_OUTCOMES_V1,
        ),
        actions=SubmissionReconciliationActionProfileV1(
            actions=SUBMISSION_RECONCILIATION_ACTIONS_V1,
            persistent_cleanup_alert_type=(
                AlertType.CIPHERTEXT_DELETE_PERSISTENT_FAILURE
            ),
        ),
        payload_policy=SubmissionReconciliationPayloadPolicyV1(
            allowed_fields=(
                SUBMISSION_RECONCILIATION_ALLOWED_PAYLOAD_FIELDS_V1
            ),
            forbidden_fields=(
                SUBMISSION_RECONCILIATION_FORBIDDEN_PAYLOAD_FIELDS_V1
            ),
        ),
    )
