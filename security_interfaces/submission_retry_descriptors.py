"""Inert duplicate/retry descriptors from the approved docs/20 flow.

This module validates only static retry and duplicate-POST outcome metadata. It
does not parse requests, compare credentials, claim attempts, inspect database
state, create reports, replay credentials, call services, expose endpoints, or
authorize submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SubmissionRetryDescriptorRejected


SUBMISSION_RETRY_PROFILE_VERSION = 1


class SubmissionRetrySource(StrEnum):
    PARALLEL_COPY = "PARALLEL_COPY"
    DELAYED_REQUEST = "DELAYED_REQUEST"
    PROXY_RETRY = "PROXY_RETRY"
    BROWSER_RETRY = "BROWSER_RETRY"
    STALE_TAB = "STALE_TAB"
    POST_ACCEPTANCE_RETRY = "POST_ACCEPTANCE_RETRY"


class SubmissionRetryRequiredOutcome(StrEnum):
    ONE_DATABASE_WINNER = "ONE_DATABASE_WINNER"
    LOSERS_START_NO_PIPELINE = "LOSERS_START_NO_PIPELINE"
    NO_SECOND_REPORT = "NO_SECOND_REPORT"
    NO_SECOND_REPORT_DEK = "NO_SECOND_REPORT_DEK"
    NO_DUPLICATE_ACCEPTANCE_EVENT = "NO_DUPLICATE_ACCEPTANCE_EVENT"
    NO_CREDENTIAL_REDISPLAY = "NO_CREDENTIAL_REDISPLAY"
    CONTROLLED_INDETERMINATE_RESPONSE = "CONTROLLED_INDETERMINATE_RESPONSE"


class SubmissionRetryForbiddenSignal(StrEnum):
    REPORT_CONTENT = "REPORT_CONTENT"
    RECOVERY_SECRET = "RECOVERY_SECRET"
    TICKET_ID = "TICKET_ID"
    ORIGINAL_FILENAME = "ORIGINAL_FILENAME"
    REQUEST_HEADER = "REQUEST_HEADER"
    IP_ADDRESS = "IP_ADDRESS"
    USER_AGENT = "USER_AGENT"
    STATUS_ORACLE = "STATUS_ORACLE"
    RAW_ERROR = "RAW_ERROR"


SUBMISSION_RETRY_SOURCES_V1 = (
    SubmissionRetrySource.PARALLEL_COPY,
    SubmissionRetrySource.DELAYED_REQUEST,
    SubmissionRetrySource.PROXY_RETRY,
    SubmissionRetrySource.BROWSER_RETRY,
    SubmissionRetrySource.STALE_TAB,
    SubmissionRetrySource.POST_ACCEPTANCE_RETRY,
)

SUBMISSION_RETRY_REQUIRED_OUTCOMES_V1 = (
    SubmissionRetryRequiredOutcome.ONE_DATABASE_WINNER,
    SubmissionRetryRequiredOutcome.LOSERS_START_NO_PIPELINE,
    SubmissionRetryRequiredOutcome.NO_SECOND_REPORT,
    SubmissionRetryRequiredOutcome.NO_SECOND_REPORT_DEK,
    SubmissionRetryRequiredOutcome.NO_DUPLICATE_ACCEPTANCE_EVENT,
    SubmissionRetryRequiredOutcome.NO_CREDENTIAL_REDISPLAY,
    SubmissionRetryRequiredOutcome.CONTROLLED_INDETERMINATE_RESPONSE,
)

SUBMISSION_RETRY_FORBIDDEN_SIGNALS_V1 = (
    SubmissionRetryForbiddenSignal.REPORT_CONTENT,
    SubmissionRetryForbiddenSignal.RECOVERY_SECRET,
    SubmissionRetryForbiddenSignal.TICKET_ID,
    SubmissionRetryForbiddenSignal.ORIGINAL_FILENAME,
    SubmissionRetryForbiddenSignal.REQUEST_HEADER,
    SubmissionRetryForbiddenSignal.IP_ADDRESS,
    SubmissionRetryForbiddenSignal.USER_AGENT,
    SubmissionRetryForbiddenSignal.STATUS_ORACLE,
    SubmissionRetryForbiddenSignal.RAW_ERROR,
)


@dataclass(frozen=True, slots=True)
class SubmissionRetrySourceProfileV1:
    sources: tuple[SubmissionRetrySource, ...]


@dataclass(frozen=True, slots=True)
class SubmissionRetryOutcomeProfileV1:
    required_outcomes: tuple[SubmissionRetryRequiredOutcome, ...]


@dataclass(frozen=True, slots=True)
class SubmissionRetrySignalPolicyV1:
    forbidden_signals: tuple[SubmissionRetryForbiddenSignal, ...]


@dataclass(frozen=True, slots=True)
class SubmissionRetryProfileV1:
    scheme_version: int
    sources: SubmissionRetrySourceProfileV1
    outcomes: SubmissionRetryOutcomeProfileV1
    signal_policy: SubmissionRetrySignalPolicyV1


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionRetryProfileV1:
    profile: SubmissionRetryProfileV1

    @property
    def parses_request(self) -> bool:
        return False

    @property
    def verifies_attempt_credential(self) -> bool:
        return False

    @property
    def claims_attempt(self) -> bool:
        return False

    @property
    def inspects_database_state(self) -> bool:
        return False

    @property
    def creates_report(self) -> bool:
        return False

    @property
    def creates_report_dek(self) -> bool:
        return False

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def redisplays_credentials(self) -> bool:
        return False

    @property
    def exposes_status_oracle(self) -> bool:
        return False

    @property
    def calls_service(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


def _reject() -> Never:
    raise SubmissionRetryDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_source(value: object) -> SubmissionRetrySource:
    if isinstance(value, SubmissionRetrySource):
        return value
    _reject()


def _require_outcome(value: object) -> SubmissionRetryRequiredOutcome:
    if isinstance(value, SubmissionRetryRequiredOutcome):
        return value
    _reject()


def _require_signal(value: object) -> SubmissionRetryForbiddenSignal:
    if isinstance(value, SubmissionRetryForbiddenSignal):
        return value
    _reject()


def _require_sources(value: object) -> tuple[SubmissionRetrySource, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_source(item) for item in value)
    if normalized != SUBMISSION_RETRY_SOURCES_V1:
        _reject()
    return normalized


def _require_outcomes(
    value: object,
) -> tuple[SubmissionRetryRequiredOutcome, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_outcome(item) for item in value)
    if normalized != SUBMISSION_RETRY_REQUIRED_OUTCOMES_V1:
        _reject()
    return normalized


def _require_forbidden_signals(
    value: object,
) -> tuple[SubmissionRetryForbiddenSignal, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_signal(item) for item in value)
    if normalized != SUBMISSION_RETRY_FORBIDDEN_SIGNALS_V1:
        _reject()
    return normalized


def validate_submission_retry_source_profile_v1(
    sources: SubmissionRetrySourceProfileV1,
) -> SubmissionRetrySourceProfileV1:
    if type(sources) is not SubmissionRetrySourceProfileV1:
        _reject()
    return SubmissionRetrySourceProfileV1(
        sources=_require_sources(sources.sources),
    )


def validate_submission_retry_outcome_profile_v1(
    outcomes: SubmissionRetryOutcomeProfileV1,
) -> SubmissionRetryOutcomeProfileV1:
    if type(outcomes) is not SubmissionRetryOutcomeProfileV1:
        _reject()
    return SubmissionRetryOutcomeProfileV1(
        required_outcomes=_require_outcomes(outcomes.required_outcomes),
    )


def validate_submission_retry_signal_policy_v1(
    signal_policy: SubmissionRetrySignalPolicyV1,
) -> SubmissionRetrySignalPolicyV1:
    if type(signal_policy) is not SubmissionRetrySignalPolicyV1:
        _reject()
    return SubmissionRetrySignalPolicyV1(
        forbidden_signals=_require_forbidden_signals(
            signal_policy.forbidden_signals
        ),
    )


def validate_submission_retry_profile_v1(
    profile: SubmissionRetryProfileV1,
) -> StructurallyValidSubmissionRetryProfileV1:
    if type(profile) is not SubmissionRetryProfileV1:
        _reject()
    normalized = SubmissionRetryProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_RETRY_PROFILE_VERSION,
        ),
        sources=validate_submission_retry_source_profile_v1(profile.sources),
        outcomes=validate_submission_retry_outcome_profile_v1(
            profile.outcomes
        ),
        signal_policy=validate_submission_retry_signal_policy_v1(
            profile.signal_policy
        ),
    )
    if normalized != expected_submission_retry_profile_v1():
        _reject()
    return StructurallyValidSubmissionRetryProfileV1(profile=normalized)


def expected_submission_retry_profile_v1() -> SubmissionRetryProfileV1:
    """Return only the approved duplicate/retry outcome metadata profile."""

    return SubmissionRetryProfileV1(
        scheme_version=SUBMISSION_RETRY_PROFILE_VERSION,
        sources=SubmissionRetrySourceProfileV1(
            sources=SUBMISSION_RETRY_SOURCES_V1,
        ),
        outcomes=SubmissionRetryOutcomeProfileV1(
            required_outcomes=SUBMISSION_RETRY_REQUIRED_OUTCOMES_V1,
        ),
        signal_policy=SubmissionRetrySignalPolicyV1(
            forbidden_signals=SUBMISSION_RETRY_FORBIDDEN_SIGNALS_V1,
        ),
    )
