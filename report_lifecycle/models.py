import uuid

from django.db import models
from django.db.models import F, Q

from .errors import LifecycleTransitionDenied
from .states import (
    LeaseState,
    ReportState,
    SecurityOperationKind,
    SecurityOperationState,
)


OPERATOR_OWNED_REPORT_STATES = (
    ReportState.CLAIMED,
    ReportState.OPEN,
    ReportState.FINALIZING,
    ReportState.DELETING,
)
TERMINAL_REPORT_STATES = (
    ReportState.DESTROYED,
    ReportState.DELETED_WITH_REASON,
    ReportState.DELETED_UNOPENED_EMERGENCY,
)
TERMINAL_LEASE_STATES = (
    LeaseState.RELEASED,
    LeaseState.EXPIRED,
    LeaseState.INVALIDATED,
)
TERMINAL_OPERATION_STATES = (
    SecurityOperationState.COMPLETED,
    SecurityOperationState.FAILED,
    SecurityOperationState.ABORTED,
)


class Report(models.Model):
    """Internal metadata only; it contains no report or recovery material."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    state = models.CharField(
        max_length=32,
        choices=ReportState.choices,
        default=ReportState.SEALED,
        editable=False,
    )
    state_version = models.PositiveBigIntegerField(default=0, editable=False)
    current_lease_generation = models.PositiveBigIntegerField(
        default=0,
        editable=False,
    )
    active_operator_id = models.UUIDField(null=True, editable=False)
    received_at = models.DateTimeField(auto_now_add=True, editable=False)
    claimed_at = models.DateTimeField(null=True, editable=False)
    claim_expires_at = models.DateTimeField(null=True, editable=False)
    response_available_at = models.DateTimeField(null=True, editable=False)
    terminal_at = models.DateTimeField(null=True, editable=False)

    class Meta:
        db_table = "report_lifecycle_report"
        default_permissions = ()
        indexes = [
            models.Index(fields=("state", "received_at"), name="report_state_received_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(state__in=ReportState.values),
                name="report_known_state",
            ),
            models.CheckConstraint(
                condition=Q(state_version__gte=0),
                name="report_nonnegative_state_version",
            ),
            models.CheckConstraint(
                condition=Q(current_lease_generation__gte=0),
                name="report_nonnegative_lease_generation",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state__in=OPERATOR_OWNED_REPORT_STATES,
                        active_operator_id__isnull=False,
                    )
                    | (
                        ~Q(state__in=OPERATOR_OWNED_REPORT_STATES)
                        & Q(active_operator_id__isnull=True)
                    )
                ),
                name="report_operator_state_shape",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state=ReportState.CLAIMED,
                        claimed_at__isnull=False,
                        claim_expires_at__isnull=False,
                        claim_expires_at__gt=F("claimed_at"),
                    )
                    | (
                        ~Q(state=ReportState.CLAIMED)
                        & Q(claimed_at__isnull=True, claim_expires_at__isnull=True)
                    )
                ),
                name="report_claim_timestamp_shape",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state__in=(ReportState.RESPONSE_AVAILABLE, ReportState.DESTROYED),
                        response_available_at__isnull=False,
                    )
                    | (
                        ~Q(
                            state__in=(
                                ReportState.RESPONSE_AVAILABLE,
                                ReportState.DESTROYED,
                            )
                        )
                        & Q(response_available_at__isnull=True)
                    )
                ),
                name="report_response_timestamp_shape",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state__in=TERMINAL_REPORT_STATES, terminal_at__isnull=False)
                    | (
                        ~Q(state__in=TERMINAL_REPORT_STATES)
                        & Q(terminal_at__isnull=True)
                    )
                ),
                name="report_terminal_timestamp_shape",
            ),
            models.UniqueConstraint(
                fields=("active_operator_id",),
                condition=Q(state__in=OPERATOR_OWNED_REPORT_STATES),
                name="one_active_report_per_operator",
            ),
        ]

    def save(self, *args: object, **kwargs: object) -> None:
        if self._state.adding:
            if (
                self.state != ReportState.SEALED
                or self.state_version != 0
                or self.current_lease_generation != 0
                or self.active_operator_id is not None
                or self.claimed_at is not None
                or self.claim_expires_at is not None
                or self.response_available_at is not None
                or self.terminal_at is not None
            ):
                raise LifecycleTransitionDenied()
        else:
            # Direct mutation stays forbidden; reviewed executors use guarded updates.
            raise LifecycleTransitionDenied()
        super().save(*args, **kwargs)


class ReportLease(models.Model):
    """Metadata fence for one OPEN period; it carries no content capability."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(
        Report,
        on_delete=models.PROTECT,
        related_name="leases",
        editable=False,
    )
    operator_id = models.UUIDField(editable=False)
    generation = models.PositiveBigIntegerField(editable=False)
    state = models.CharField(
        max_length=12,
        choices=LeaseState.choices,
        default=LeaseState.ACTIVE,
        editable=False,
    )
    state_version = models.PositiveBigIntegerField(default=0, editable=False)
    opened_at = models.DateTimeField(editable=False)
    last_activity_at = models.DateTimeField(editable=False)
    absolute_expires_at = models.DateTimeField(editable=False)
    closed_at = models.DateTimeField(null=True, editable=False)

    class Meta:
        db_table = "report_lifecycle_lease"
        default_permissions = ()
        indexes = [
            models.Index(
                fields=("state", "absolute_expires_at"),
                name="lease_state_expiry_idx",
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(state__in=LeaseState.values),
                name="lease_known_state",
            ),
            models.CheckConstraint(
                condition=Q(generation__gte=1),
                name="lease_positive_generation",
            ),
            models.CheckConstraint(
                condition=Q(state_version__gte=0),
                name="lease_nonnegative_state_version",
            ),
            models.CheckConstraint(
                condition=(
                    Q(last_activity_at__gte=F("opened_at"))
                    & Q(absolute_expires_at__gt=F("opened_at"))
                    & Q(last_activity_at__lt=F("absolute_expires_at"))
                ),
                name="lease_time_order",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state=LeaseState.ACTIVE, closed_at__isnull=True)
                    | Q(state__in=TERMINAL_LEASE_STATES, closed_at__isnull=False)
                ),
                name="lease_closed_timestamp_shape",
            ),
            models.UniqueConstraint(
                fields=("report", "generation"),
                name="one_lease_generation_per_report",
            ),
            models.UniqueConstraint(
                fields=("report",),
                condition=Q(state=LeaseState.ACTIVE),
                name="one_active_lease_per_report",
            ),
            models.UniqueConstraint(
                fields=("operator_id",),
                condition=Q(state=LeaseState.ACTIVE),
                name="one_active_lease_per_operator",
            ),
        ]

    def save(self, *args: object, **kwargs: object) -> None:
        if self._state.adding:
            if (
                self.state != LeaseState.ACTIVE
                or self.state_version != 0
                or self.closed_at is not None
            ):
                raise LifecycleTransitionDenied()
        else:
            raise LifecycleTransitionDenied()
        super().save(*args, **kwargs)


class SecurityOperation(models.Model):
    """Immutable-context metadata for one fenced security operation."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(
        Report,
        on_delete=models.PROTECT,
        related_name="security_operations",
        editable=False,
    )
    kind = models.CharField(
        max_length=24,
        choices=SecurityOperationKind.choices,
        editable=False,
    )
    state = models.CharField(
        max_length=12,
        choices=SecurityOperationState.choices,
        default=SecurityOperationState.PREPARED,
        editable=False,
    )
    state_version = models.PositiveBigIntegerField(default=0, editable=False)
    bound_report_version = models.PositiveBigIntegerField(editable=False)
    fence_token = models.PositiveBigIntegerField(editable=False)
    idempotency_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    actor_id = models.UUIDField(editable=False)
    lease = models.ForeignKey(
        ReportLease,
        on_delete=models.PROTECT,
        related_name="security_operations",
        null=True,
        editable=False,
    )
    lease_generation = models.PositiveBigIntegerField(null=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    activated_at = models.DateTimeField(null=True, editable=False)
    terminal_at = models.DateTimeField(null=True, editable=False)

    class Meta:
        db_table = "report_lifecycle_security_operation"
        default_permissions = ()
        indexes = [
            models.Index(fields=("state", "created_at"), name="operation_state_created_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(kind__in=SecurityOperationKind.values),
                name="operation_known_kind",
            ),
            models.CheckConstraint(
                condition=Q(state__in=SecurityOperationState.values),
                name="operation_known_state",
            ),
            models.CheckConstraint(
                condition=Q(state_version__gte=0, bound_report_version__gte=0),
                name="operation_nonnegative_versions",
            ),
            models.CheckConstraint(
                condition=Q(fence_token__gte=1),
                name="operation_positive_fence",
            ),
            models.CheckConstraint(
                condition=(
                    Q(lease__isnull=True, lease_generation__isnull=True)
                    | Q(lease__isnull=False, lease_generation__gte=1)
                ),
                name="operation_lease_binding_shape",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state=SecurityOperationState.PREPARED,
                        activated_at__isnull=True,
                        terminal_at__isnull=True,
                    )
                    | Q(
                        state=SecurityOperationState.ACTIVE,
                        activated_at__isnull=False,
                        terminal_at__isnull=True,
                    )
                    | Q(
                        state__in=TERMINAL_OPERATION_STATES,
                        terminal_at__isnull=False,
                    )
                ),
                name="operation_timestamp_shape",
            ),
            models.UniqueConstraint(
                fields=("report", "fence_token"),
                name="one_operation_fence_token_per_report",
            ),
            models.UniqueConstraint(
                fields=("report",),
                condition=Q(state=SecurityOperationState.ACTIVE),
                name="one_active_operation_per_report",
            ),
        ]

    def save(self, *args: object, **kwargs: object) -> None:
        if self._state.adding:
            if (
                self.state != SecurityOperationState.PREPARED
                or self.state_version != 0
                or self.activated_at is not None
                or self.terminal_at is not None
            ):
                raise LifecycleTransitionDenied()
        else:
            raise LifecycleTransitionDenied()
        super().save(*args, **kwargs)
