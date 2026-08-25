from types import MappingProxyType

from django.db import models

from .errors import SubmissionTransitionDenied


class SubmissionAttemptState(models.TextChoices):
    READY = "READY", "Ready"
    PROCESSING = "PROCESSING", "Processing"
    CIPHERTEXT_STAGED = "CIPHERTEXT_STAGED", "Ciphertext staged"
    AUDIT_CONFIRMED = "AUDIT_CONFIRMED", "Audit confirmed"
    ACCEPTED = "ACCEPTED", "Accepted"
    ABORTING = "ABORTING", "Aborting"
    ABORTED = "ABORTED", "Aborted"


ALLOWED_TRANSITIONS = MappingProxyType(
    {
        SubmissionAttemptState.READY: frozenset(
            {SubmissionAttemptState.PROCESSING, SubmissionAttemptState.ABORTING}
        ),
        SubmissionAttemptState.PROCESSING: frozenset(
            {
                SubmissionAttemptState.CIPHERTEXT_STAGED,
                SubmissionAttemptState.ABORTING,
            }
        ),
        SubmissionAttemptState.CIPHERTEXT_STAGED: frozenset(
            {
                SubmissionAttemptState.AUDIT_CONFIRMED,
                SubmissionAttemptState.ABORTING,
            }
        ),
        SubmissionAttemptState.AUDIT_CONFIRMED: frozenset(
            {SubmissionAttemptState.ACCEPTED, SubmissionAttemptState.ABORTING}
        ),
        SubmissionAttemptState.ACCEPTED: frozenset(),
        SubmissionAttemptState.ABORTING: frozenset(
            {SubmissionAttemptState.ABORTED}
        ),
        SubmissionAttemptState.ABORTED: frozenset(),
    }
)


def normalize_state(value: str | SubmissionAttemptState) -> SubmissionAttemptState:
    try:
        return SubmissionAttemptState(value)
    except (TypeError, ValueError) as error:
        raise SubmissionTransitionDenied() from error


def require_allowed_transition(
    current_state: str | SubmissionAttemptState,
    target_state: str | SubmissionAttemptState,
) -> tuple[SubmissionAttemptState, SubmissionAttemptState]:
    current = normalize_state(current_state)
    target = normalize_state(target_state)

    if target not in ALLOWED_TRANSITIONS[current]:
        raise SubmissionTransitionDenied()

    return current, target
