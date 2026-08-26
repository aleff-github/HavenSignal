from types import MappingProxyType

from django.db import models

from .errors import LifecycleTransitionDenied


class ReportState(models.TextChoices):
    SEALED = "SEALED", "Sealed"
    CLAIMED = "CLAIMED", "Claimed"
    OPEN = "OPEN", "Open"
    INTERRUPTED = "INTERRUPTED", "Interrupted"
    FINALIZING = "FINALIZING", "Finalizing"
    RESPONSE_AVAILABLE = "RESPONSE_AVAILABLE", "Response available"
    DELETING = "DELETING", "Deleting"
    DELETING_FLOOD = "DELETING_FLOOD", "Deleting during flood"
    DESTROYED = "DESTROYED", "Destroyed"
    DELETED_WITH_REASON = "DELETED_WITH_REASON", "Deleted with reason"
    DELETED_UNOPENED_EMERGENCY = (
        "DELETED_UNOPENED_EMERGENCY",
        "Deleted unopened during emergency",
    )


class LeaseState(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    RELEASED = "RELEASED", "Released"
    EXPIRED = "EXPIRED", "Expired"
    INVALIDATED = "INVALIDATED", "Invalidated"


class SecurityOperationKind(models.TextChoices):
    REOPEN_REPORT = "REOPEN_REPORT", "Reopen report"
    FINALIZE_RESPONSE = "FINALIZE_RESPONSE", "Finalize response"
    EMERGENCY_EXPORT = "EMERGENCY_EXPORT", "Emergency export"
    DELETE_REPORT = "DELETE_REPORT", "Delete report"
    DELETE_REPORT_FLOOD = "DELETE_REPORT_FLOOD", "Delete report during flood"


class SecurityOperationState(models.TextChoices):
    PREPARED = "PREPARED", "Prepared"
    ACTIVE = "ACTIVE", "Active"
    COMPLETED = "COMPLETED", "Completed"
    FAILED = "FAILED", "Failed"
    ABORTED = "ABORTED", "Aborted"


REPORT_TRANSITIONS = MappingProxyType(
    {
        ReportState.SEALED: frozenset(
            {ReportState.CLAIMED, ReportState.DELETING_FLOOD}
        ),
        ReportState.CLAIMED: frozenset({ReportState.SEALED, ReportState.OPEN}),
        ReportState.OPEN: frozenset(
            {
                ReportState.INTERRUPTED,
                ReportState.FINALIZING,
                ReportState.DELETING,
            }
        ),
        ReportState.INTERRUPTED: frozenset({ReportState.OPEN}),
        ReportState.FINALIZING: frozenset({ReportState.RESPONSE_AVAILABLE}),
        ReportState.RESPONSE_AVAILABLE: frozenset({ReportState.DESTROYED}),
        ReportState.DELETING: frozenset({ReportState.DELETED_WITH_REASON}),
        ReportState.DELETING_FLOOD: frozenset(
            {ReportState.DELETED_UNOPENED_EMERGENCY}
        ),
        ReportState.DESTROYED: frozenset(),
        ReportState.DELETED_WITH_REASON: frozenset(),
        ReportState.DELETED_UNOPENED_EMERGENCY: frozenset(),
    }
)

LEASE_TRANSITIONS = MappingProxyType(
    {
        LeaseState.ACTIVE: frozenset(
            {LeaseState.RELEASED, LeaseState.EXPIRED, LeaseState.INVALIDATED}
        ),
        LeaseState.RELEASED: frozenset(),
        LeaseState.EXPIRED: frozenset(),
        LeaseState.INVALIDATED: frozenset(),
    }
)

SECURITY_OPERATION_TRANSITIONS = MappingProxyType(
    {
        SecurityOperationState.PREPARED: frozenset(
            {SecurityOperationState.ACTIVE, SecurityOperationState.ABORTED}
        ),
        SecurityOperationState.ACTIVE: frozenset(
            {
                SecurityOperationState.COMPLETED,
                SecurityOperationState.FAILED,
                SecurityOperationState.ABORTED,
            }
        ),
        SecurityOperationState.COMPLETED: frozenset(),
        SecurityOperationState.FAILED: frozenset(),
        SecurityOperationState.ABORTED: frozenset(),
    }
)


def _require_transition(
    *,
    current_state: str,
    target_state: str,
    state_type: type[models.TextChoices],
    transitions: MappingProxyType,
) -> tuple[models.TextChoices, models.TextChoices]:
    try:
        current = state_type(current_state)
        target = state_type(target_state)
    except (TypeError, ValueError) as error:
        raise LifecycleTransitionDenied() from error

    if target not in transitions[current]:
        raise LifecycleTransitionDenied()
    return current, target


def require_report_transition(
    current_state: str | ReportState,
    target_state: str | ReportState,
) -> tuple[ReportState, ReportState]:
    current, target = _require_transition(
        current_state=current_state,
        target_state=target_state,
        state_type=ReportState,
        transitions=REPORT_TRANSITIONS,
    )
    return ReportState(current), ReportState(target)


def require_lease_transition(
    current_state: str | LeaseState,
    target_state: str | LeaseState,
) -> tuple[LeaseState, LeaseState]:
    current, target = _require_transition(
        current_state=current_state,
        target_state=target_state,
        state_type=LeaseState,
        transitions=LEASE_TRANSITIONS,
    )
    return LeaseState(current), LeaseState(target)


def require_security_operation_transition(
    current_state: str | SecurityOperationState,
    target_state: str | SecurityOperationState,
) -> tuple[SecurityOperationState, SecurityOperationState]:
    current, target = _require_transition(
        current_state=current_state,
        target_state=target_state,
        state_type=SecurityOperationState,
        transitions=SECURITY_OPERATION_TRANSITIONS,
    )
    return SecurityOperationState(current), SecurityOperationState(target)
