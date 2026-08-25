import uuid

from django.db import models
from django.db.models import Q

from .errors import SubmissionTransitionDenied
from .states import SubmissionAttemptState


class SubmissionAttempt(models.Model):
    """Metadata-only state for the approved pre-acceptance protocol.

    The UUID is an internal coordinator identifier. It is not the browser's
    submission-attempt credential, a Ticket ID, or a report identifier.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    state = models.CharField(
        max_length=20,
        choices=SubmissionAttemptState.choices,
        default=SubmissionAttemptState.READY,
        editable=False,
    )
    state_version = models.PositiveBigIntegerField(default=0, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    last_progress_at = models.DateTimeField(auto_now_add=True, editable=False)
    accepted_at = models.DateTimeField(null=True, editable=False)
    aborting_at = models.DateTimeField(null=True, editable=False)
    aborted_at = models.DateTimeField(null=True, editable=False)

    class Meta:
        db_table = "submission_attempt"
        default_permissions = ()
        constraints = [
            models.CheckConstraint(
                condition=Q(state__in=SubmissionAttemptState.values),
                name="submission_attempt_known_state",
            ),
            models.CheckConstraint(
                condition=Q(state_version__gte=0),
                name="submission_attempt_nonnegative_version",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state=SubmissionAttemptState.READY, state_version=0)
                    | Q(state=SubmissionAttemptState.PROCESSING, state_version=1)
                    | Q(
                        state=SubmissionAttemptState.CIPHERTEXT_STAGED,
                        state_version=2,
                    )
                    | Q(
                        state=SubmissionAttemptState.AUDIT_CONFIRMED,
                        state_version=3,
                    )
                    | Q(state=SubmissionAttemptState.ACCEPTED, state_version=4)
                    | Q(
                        state=SubmissionAttemptState.ABORTING,
                        state_version__gte=1,
                        state_version__lte=4,
                    )
                    | Q(
                        state=SubmissionAttemptState.ABORTED,
                        state_version__gte=2,
                        state_version__lte=5,
                    )
                ),
                name="submission_attempt_state_version_shape",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state=SubmissionAttemptState.ACCEPTED,
                        accepted_at__isnull=False,
                    )
                    | (
                        ~Q(state=SubmissionAttemptState.ACCEPTED)
                        & Q(accepted_at__isnull=True)
                    )
                ),
                name="submission_attempt_accepted_timestamp",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state__in=(
                            SubmissionAttemptState.ABORTING,
                            SubmissionAttemptState.ABORTED,
                        ),
                        aborting_at__isnull=False,
                    )
                    | (
                        ~Q(
                            state__in=(
                                SubmissionAttemptState.ABORTING,
                                SubmissionAttemptState.ABORTED,
                            )
                        )
                        & Q(aborting_at__isnull=True)
                    )
                ),
                name="submission_attempt_aborting_timestamp",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state=SubmissionAttemptState.ABORTED,
                        aborted_at__isnull=False,
                    )
                    | (
                        ~Q(state=SubmissionAttemptState.ABORTED)
                        & Q(aborted_at__isnull=True)
                    )
                ),
                name="submission_attempt_aborted_timestamp",
            ),
        ]

    def save(self, *args: object, **kwargs: object) -> None:
        if self._state.adding:
            if (
                self.state != SubmissionAttemptState.READY
                or self.state_version != 0
                or self.accepted_at is not None
                or self.aborting_at is not None
                or self.aborted_at is not None
            ):
                raise SubmissionTransitionDenied()
        else:
            # Existing rows await a separately reviewed fenced persistence executor.
            raise SubmissionTransitionDenied()

        super().save(*args, **kwargs)
