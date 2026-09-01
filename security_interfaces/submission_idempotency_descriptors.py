"""Inert submission idempotency descriptors from docs/20.

This module validates only static concurrency/idempotency test-invariant
metadata for the approved submission acceptance protocol. It does not run
parallel requests, inspect attempts, lock rows, write storage, create keys,
append audit events, reconcile artifacts, log inputs, expose endpoints, or
authorize submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SubmissionIdempotencyDescriptorRejected


SUBMISSION_IDEMPOTENCY_PROFILE_VERSION = 1


class SubmissionIdempotencyScenario(StrEnum):
    SEQUENTIAL_RETRY_EVERY_TRANSITION = "SEQUENTIAL_RETRY_EVERY_TRANSITION"
    SYNCHRONIZED_PARALLEL_COPY_EVERY_TRANSITION = (
        "SYNCHRONIZED_PARALLEL_COPY_EVERY_TRANSITION"
    )
    MULTIPLE_APPLICATION_PROCESSES = "MULTIPLE_APPLICATION_PROCESSES"
    RECONCILIATION_AFTER_DUPLICATE_ARTIFACTS = (
        "RECONCILIATION_AFTER_DUPLICATE_ARTIFACTS"
    )
    STALE_VERSION_AFTER_RECEIPT = "STALE_VERSION_AFTER_RECEIPT"
    RESPONSE_LOSS_AFTER_SEALED = "RESPONSE_LOSS_AFTER_SEALED"
    CRASH_INJECTION_AT_NUMBERED_STEPS = "CRASH_INJECTION_AT_NUMBERED_STEPS"
    CLEANUP_AFTER_ABORT_OR_KEY_DESTRUCTION = (
        "CLEANUP_AFTER_ABORT_OR_KEY_DESTRUCTION"
    )
    LOGGING_DURING_FAILURE = "LOGGING_DURING_FAILURE"


class SubmissionIdempotencyInvariant(StrEnum):
    EXACTLY_ONE_ATTEMPT_OWNER = "EXACTLY_ONE_ATTEMPT_OWNER"
    AT_MOST_ONE_SEALED_REPORT_PER_ATTEMPT = (
        "AT_MOST_ONE_SEALED_REPORT_PER_ATTEMPT"
    )
    DATABASE_UNIQUENESS_AUTHORITATIVE_ACROSS_PROCESSES = (
        "DATABASE_UNIQUENESS_AUTHORITATIVE_ACROSS_PROCESSES"
    )
    NO_DUPLICATE_REPORT_DEK_SURVIVES_RECONCILIATION = (
        "NO_DUPLICATE_REPORT_DEK_SURVIVES_RECONCILIATION"
    )
    NO_DUPLICATE_METADATA_ROW_SURVIVES_RECONCILIATION = (
        "NO_DUPLICATE_METADATA_ROW_SURVIVES_RECONCILIATION"
    )
    NO_DUPLICATE_CIPHERTEXT_OBJECT_SURVIVES_RECONCILIATION = (
        "NO_DUPLICATE_CIPHERTEXT_OBJECT_SURVIVES_RECONCILIATION"
    )
    NO_DUPLICATE_ACCEPTANCE_EVENT_SURVIVES_RECONCILIATION = (
        "NO_DUPLICATE_ACCEPTANCE_EVENT_SURVIVES_RECONCILIATION"
    )
    STALE_VERSION_CANNOT_APPEND_USABLE_RECEIPT = (
        "STALE_VERSION_CANNOT_APPEND_USABLE_RECEIPT"
    )
    STALE_VERSION_CANNOT_COMMIT_SEALED = "STALE_VERSION_CANNOT_COMMIT_SEALED"
    RESPONSE_LOSS_CANNOT_AUTHORIZE_CREDENTIAL_REPLAY = (
        "RESPONSE_LOSS_CANNOT_AUTHORIZE_CREDENTIAL_REPLAY"
    )
    RESPONSE_LOSS_CANNOT_AUTHORIZE_SECOND_SUBMISSION = (
        "RESPONSE_LOSS_CANNOT_AUTHORIZE_SECOND_SUBMISSION"
    )
    CRASH_INJECTION_REACHES_ONLY_ALLOWED_STATE = (
        "CRASH_INJECTION_REACHES_ONLY_ALLOWED_STATE"
    )
    CLEANUP_CANNOT_RESURRECT_STAGED_CONTENT = (
        "CLEANUP_CANNOT_RESURRECT_STAGED_CONTENT"
    )
    CLEANUP_CANNOT_DECRYPT_STAGED_CONTENT = "CLEANUP_CANNOT_DECRYPT_STAGED_CONTENT"
    CLEANUP_CANNOT_EXPOSE_STAGED_CONTENT = "CLEANUP_CANNOT_EXPOSE_STAGED_CONTENT"
    NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_LOGS = (
        "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_LOGS"
    )
    NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_AUDIT = (
        "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_AUDIT"
    )
    NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_ALERTS = (
        "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_ALERTS"
    )
    NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_TRACING = (
        "NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_TRACING"
    )


class SubmissionIdempotencyForbiddenCapability(StrEnum):
    RUNS_PARALLEL_REQUESTS = "RUNS_PARALLEL_REQUESTS"
    HANDLES_REQUEST = "HANDLES_REQUEST"
    INSPECTS_ATTEMPT_STATE = "INSPECTS_ATTEMPT_STATE"
    LOCKS_DATABASE_ROW = "LOCKS_DATABASE_ROW"
    WRITES_STORAGE = "WRITES_STORAGE"
    CREATES_REPORT_DEK = "CREATES_REPORT_DEK"
    APPENDS_AUDIT_EVENT = "APPENDS_AUDIT_EVENT"
    RECONCILES_ARTIFACTS = "RECONCILES_ARTIFACTS"
    LOGS_REPORTER_INPUT = "LOGS_REPORTER_INPUT"
    EXPOSES_ENDPOINT = "EXPOSES_ENDPOINT"
    AUTHORIZES_SUBMISSION = "AUTHORIZES_SUBMISSION"


SUBMISSION_IDEMPOTENCY_SCENARIOS_V1 = (
    SubmissionIdempotencyScenario.SEQUENTIAL_RETRY_EVERY_TRANSITION,
    SubmissionIdempotencyScenario.SYNCHRONIZED_PARALLEL_COPY_EVERY_TRANSITION,
    SubmissionIdempotencyScenario.MULTIPLE_APPLICATION_PROCESSES,
    SubmissionIdempotencyScenario.RECONCILIATION_AFTER_DUPLICATE_ARTIFACTS,
    SubmissionIdempotencyScenario.STALE_VERSION_AFTER_RECEIPT,
    SubmissionIdempotencyScenario.RESPONSE_LOSS_AFTER_SEALED,
    SubmissionIdempotencyScenario.CRASH_INJECTION_AT_NUMBERED_STEPS,
    SubmissionIdempotencyScenario.CLEANUP_AFTER_ABORT_OR_KEY_DESTRUCTION,
    SubmissionIdempotencyScenario.LOGGING_DURING_FAILURE,
)

SUBMISSION_IDEMPOTENCY_INVARIANTS_V1 = (
    SubmissionIdempotencyInvariant.EXACTLY_ONE_ATTEMPT_OWNER,
    SubmissionIdempotencyInvariant.AT_MOST_ONE_SEALED_REPORT_PER_ATTEMPT,
    (
        SubmissionIdempotencyInvariant.
        DATABASE_UNIQUENESS_AUTHORITATIVE_ACROSS_PROCESSES
    ),
    SubmissionIdempotencyInvariant.NO_DUPLICATE_REPORT_DEK_SURVIVES_RECONCILIATION,
    SubmissionIdempotencyInvariant.NO_DUPLICATE_METADATA_ROW_SURVIVES_RECONCILIATION,
    (
        SubmissionIdempotencyInvariant.
        NO_DUPLICATE_CIPHERTEXT_OBJECT_SURVIVES_RECONCILIATION
    ),
    (
        SubmissionIdempotencyInvariant.
        NO_DUPLICATE_ACCEPTANCE_EVENT_SURVIVES_RECONCILIATION
    ),
    SubmissionIdempotencyInvariant.STALE_VERSION_CANNOT_APPEND_USABLE_RECEIPT,
    SubmissionIdempotencyInvariant.STALE_VERSION_CANNOT_COMMIT_SEALED,
    (
        SubmissionIdempotencyInvariant.
        RESPONSE_LOSS_CANNOT_AUTHORIZE_CREDENTIAL_REPLAY
    ),
    (
        SubmissionIdempotencyInvariant.
        RESPONSE_LOSS_CANNOT_AUTHORIZE_SECOND_SUBMISSION
    ),
    SubmissionIdempotencyInvariant.CRASH_INJECTION_REACHES_ONLY_ALLOWED_STATE,
    SubmissionIdempotencyInvariant.CLEANUP_CANNOT_RESURRECT_STAGED_CONTENT,
    SubmissionIdempotencyInvariant.CLEANUP_CANNOT_DECRYPT_STAGED_CONTENT,
    SubmissionIdempotencyInvariant.CLEANUP_CANNOT_EXPOSE_STAGED_CONTENT,
    (
        SubmissionIdempotencyInvariant.
        NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_LOGS
    ),
    (
        SubmissionIdempotencyInvariant.
        NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_AUDIT
    ),
    (
        SubmissionIdempotencyInvariant.
        NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_ALERTS
    ),
    (
        SubmissionIdempotencyInvariant.
        NO_ORIGINAL_FILENAME_BODY_CONTENT_SECRET_OR_RAW_ERROR_IN_TRACING
    ),
)

SUBMISSION_IDEMPOTENCY_FORBIDDEN_CAPABILITIES_V1 = (
    SubmissionIdempotencyForbiddenCapability.RUNS_PARALLEL_REQUESTS,
    SubmissionIdempotencyForbiddenCapability.HANDLES_REQUEST,
    SubmissionIdempotencyForbiddenCapability.INSPECTS_ATTEMPT_STATE,
    SubmissionIdempotencyForbiddenCapability.LOCKS_DATABASE_ROW,
    SubmissionIdempotencyForbiddenCapability.WRITES_STORAGE,
    SubmissionIdempotencyForbiddenCapability.CREATES_REPORT_DEK,
    SubmissionIdempotencyForbiddenCapability.APPENDS_AUDIT_EVENT,
    SubmissionIdempotencyForbiddenCapability.RECONCILES_ARTIFACTS,
    SubmissionIdempotencyForbiddenCapability.LOGS_REPORTER_INPUT,
    SubmissionIdempotencyForbiddenCapability.EXPOSES_ENDPOINT,
    SubmissionIdempotencyForbiddenCapability.AUTHORIZES_SUBMISSION,
)


@dataclass(frozen=True, slots=True)
class SubmissionIdempotencyScenarioProfileV1:
    scenarios: tuple[SubmissionIdempotencyScenario, ...]


@dataclass(frozen=True, slots=True)
class SubmissionIdempotencyInvariantProfileV1:
    invariants: tuple[SubmissionIdempotencyInvariant, ...]


@dataclass(frozen=True, slots=True)
class SubmissionIdempotencyForbiddenCapabilityProfileV1:
    forbidden_capabilities: tuple[SubmissionIdempotencyForbiddenCapability, ...]


@dataclass(frozen=True, slots=True)
class SubmissionIdempotencyProfileV1:
    scheme_version: int
    scenarios: SubmissionIdempotencyScenarioProfileV1
    invariants: SubmissionIdempotencyInvariantProfileV1
    forbidden_capabilities: SubmissionIdempotencyForbiddenCapabilityProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionIdempotencyProfileV1:
    profile: SubmissionIdempotencyProfileV1

    @property
    def runs_parallel_requests(self) -> bool:
        return False

    @property
    def handles_request(self) -> bool:
        return False

    @property
    def inspects_attempt_state(self) -> bool:
        return False

    @property
    def locks_database_row(self) -> bool:
        return False

    @property
    def writes_storage(self) -> bool:
        return False

    @property
    def creates_report_dek(self) -> bool:
        return False

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def reconciles_artifacts(self) -> bool:
        return False

    @property
    def logs_reporter_input(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionIdempotencyDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_scenario(value: object) -> SubmissionIdempotencyScenario:
    if isinstance(value, SubmissionIdempotencyScenario):
        return value
    _reject()


def _require_invariant(value: object) -> SubmissionIdempotencyInvariant:
    if isinstance(value, SubmissionIdempotencyInvariant):
        return value
    _reject()


def _require_forbidden_capability(
    value: object,
) -> SubmissionIdempotencyForbiddenCapability:
    if isinstance(value, SubmissionIdempotencyForbiddenCapability):
        return value
    _reject()


def _require_scenarios(
    value: object,
) -> tuple[SubmissionIdempotencyScenario, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_scenario(item) for item in value)
    if normalized != SUBMISSION_IDEMPOTENCY_SCENARIOS_V1:
        _reject()
    return normalized


def _require_invariants(
    value: object,
) -> tuple[SubmissionIdempotencyInvariant, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_invariant(item) for item in value)
    if normalized != SUBMISSION_IDEMPOTENCY_INVARIANTS_V1:
        _reject()
    return normalized


def _require_forbidden_capabilities(
    value: object,
) -> tuple[SubmissionIdempotencyForbiddenCapability, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_capability(item) for item in value)
    if normalized != SUBMISSION_IDEMPOTENCY_FORBIDDEN_CAPABILITIES_V1:
        _reject()
    return normalized


def validate_submission_idempotency_scenario_profile_v1(
    scenarios: SubmissionIdempotencyScenarioProfileV1,
) -> SubmissionIdempotencyScenarioProfileV1:
    if type(scenarios) is not SubmissionIdempotencyScenarioProfileV1:
        _reject()
    return SubmissionIdempotencyScenarioProfileV1(
        scenarios=_require_scenarios(scenarios.scenarios),
    )


def validate_submission_idempotency_invariant_profile_v1(
    invariants: SubmissionIdempotencyInvariantProfileV1,
) -> SubmissionIdempotencyInvariantProfileV1:
    if type(invariants) is not SubmissionIdempotencyInvariantProfileV1:
        _reject()
    return SubmissionIdempotencyInvariantProfileV1(
        invariants=_require_invariants(invariants.invariants),
    )


def validate_submission_idempotency_forbidden_capability_profile_v1(
    forbidden_capabilities: SubmissionIdempotencyForbiddenCapabilityProfileV1,
) -> SubmissionIdempotencyForbiddenCapabilityProfileV1:
    if (
        type(forbidden_capabilities)
        is not SubmissionIdempotencyForbiddenCapabilityProfileV1
    ):
        _reject()
    return SubmissionIdempotencyForbiddenCapabilityProfileV1(
        forbidden_capabilities=_require_forbidden_capabilities(
            forbidden_capabilities.forbidden_capabilities
        ),
    )


def validate_submission_idempotency_profile_v1(
    profile: SubmissionIdempotencyProfileV1,
) -> StructurallyValidSubmissionIdempotencyProfileV1:
    if type(profile) is not SubmissionIdempotencyProfileV1:
        _reject()
    normalized = SubmissionIdempotencyProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_IDEMPOTENCY_PROFILE_VERSION,
        ),
        scenarios=validate_submission_idempotency_scenario_profile_v1(
            profile.scenarios
        ),
        invariants=validate_submission_idempotency_invariant_profile_v1(
            profile.invariants
        ),
        forbidden_capabilities=(
            validate_submission_idempotency_forbidden_capability_profile_v1(
                profile.forbidden_capabilities
            )
        ),
    )
    expected = expected_submission_idempotency_profile_v1()
    if normalized != expected:
        _reject()
    return StructurallyValidSubmissionIdempotencyProfileV1(normalized)


def expected_submission_idempotency_profile_v1() -> SubmissionIdempotencyProfileV1:
    return SubmissionIdempotencyProfileV1(
        scheme_version=SUBMISSION_IDEMPOTENCY_PROFILE_VERSION,
        scenarios=SubmissionIdempotencyScenarioProfileV1(
            scenarios=SUBMISSION_IDEMPOTENCY_SCENARIOS_V1,
        ),
        invariants=SubmissionIdempotencyInvariantProfileV1(
            invariants=SUBMISSION_IDEMPOTENCY_INVARIANTS_V1,
        ),
        forbidden_capabilities=SubmissionIdempotencyForbiddenCapabilityProfileV1(
            forbidden_capabilities=(
                SUBMISSION_IDEMPOTENCY_FORBIDDEN_CAPABILITIES_V1
            ),
        ),
    )
