from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from django.utils import timezone

from .errors import SubmissionTransitionDenied
from .states import SubmissionAttemptState, require_allowed_transition


MAX_STATE_VERSION = 9_223_372_036_854_775_807


@dataclass(frozen=True, slots=True)
class SubmissionTransitionPlan:
    attempt_id: UUID
    current_state: SubmissionAttemptState
    current_version: int
    target_state: SubmissionAttemptState
    target_version: int
    changed_at: datetime


def plan_submission_transition(
    *,
    attempt_id: UUID,
    current_state: str | SubmissionAttemptState,
    current_version: int,
    target_state: str | SubmissionAttemptState,
) -> SubmissionTransitionPlan:
    """Validate one approved edge and compute its monotonic next version.

    This planner never writes the database. The persistence executor remains
    absent until its PostgreSQL concurrency tests and every dependency needed
    by a protected transition are approved. The caller cannot supply time,
    skip a state, or select the resulting version.
    """

    current, target = require_allowed_transition(current_state, target_state)
    if (
        not isinstance(attempt_id, UUID)
        or isinstance(current_version, bool)
        or not isinstance(current_version, int)
        or current_version < 0
        or current_version >= MAX_STATE_VERSION
    ):
        raise SubmissionTransitionDenied()

    return SubmissionTransitionPlan(
        attempt_id=attempt_id,
        current_state=current,
        current_version=current_version,
        target_state=target,
        target_version=current_version + 1,
        changed_at=timezone.now(),
    )
