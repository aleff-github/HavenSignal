# Generated for Django 5.2.17 on 2026-08-25.

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="SubmissionAttempt",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("READY", "Ready"),
                            ("PROCESSING", "Processing"),
                            ("CIPHERTEXT_STAGED", "Ciphertext staged"),
                            ("AUDIT_CONFIRMED", "Audit confirmed"),
                            ("ACCEPTED", "Accepted"),
                            ("ABORTING", "Aborting"),
                            ("ABORTED", "Aborted"),
                        ],
                        default="READY",
                        editable=False,
                        max_length=20,
                    ),
                ),
                (
                    "state_version",
                    models.PositiveBigIntegerField(default=0, editable=False),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_progress_at", models.DateTimeField(auto_now_add=True)),
                ("accepted_at", models.DateTimeField(editable=False, null=True)),
                ("aborting_at", models.DateTimeField(editable=False, null=True)),
                ("aborted_at", models.DateTimeField(editable=False, null=True)),
            ],
            options={
                "db_table": "submission_attempt",
                "default_permissions": (),
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(
                            (
                                "state__in",
                                [
                                    "READY",
                                    "PROCESSING",
                                    "CIPHERTEXT_STAGED",
                                    "AUDIT_CONFIRMED",
                                    "ACCEPTED",
                                    "ABORTING",
                                    "ABORTED",
                                ],
                            )
                        ),
                        name="submission_attempt_known_state",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("state_version__gte", 0)),
                        name="submission_attempt_nonnegative_version",
                    ),
                    models.CheckConstraint(
                        condition=(
                            models.Q(("state", "READY"), ("state_version", 0))
                            | models.Q(
                                ("state", "PROCESSING"), ("state_version", 1)
                            )
                            | models.Q(
                                ("state", "CIPHERTEXT_STAGED"),
                                ("state_version", 2),
                            )
                            | models.Q(
                                ("state", "AUDIT_CONFIRMED"),
                                ("state_version", 3),
                            )
                            | models.Q(
                                ("state", "ACCEPTED"), ("state_version", 4)
                            )
                            | models.Q(
                                ("state", "ABORTING"),
                                ("state_version__gte", 1),
                                ("state_version__lte", 4),
                            )
                            | models.Q(
                                ("state", "ABORTED"),
                                ("state_version__gte", 2),
                                ("state_version__lte", 5),
                            )
                        ),
                        name="submission_attempt_state_version_shape",
                    ),
                    models.CheckConstraint(
                        condition=(
                            models.Q(
                                ("accepted_at__isnull", False),
                                ("state", "ACCEPTED"),
                            )
                            | (
                                ~models.Q(("state", "ACCEPTED"))
                                & models.Q(("accepted_at__isnull", True))
                            )
                        ),
                        name="submission_attempt_accepted_timestamp",
                    ),
                    models.CheckConstraint(
                        condition=(
                            models.Q(
                                ("aborting_at__isnull", False),
                                ("state__in", ("ABORTING", "ABORTED")),
                            )
                            | (
                                ~models.Q(
                                    ("state__in", ("ABORTING", "ABORTED"))
                                )
                                & models.Q(("aborting_at__isnull", True))
                            )
                        ),
                        name="submission_attempt_aborting_timestamp",
                    ),
                    models.CheckConstraint(
                        condition=(
                            models.Q(
                                ("aborted_at__isnull", False),
                                ("state", "ABORTED"),
                            )
                            | (
                                ~models.Q(("state", "ABORTED"))
                                & models.Q(("aborted_at__isnull", True))
                            )
                        ),
                        name="submission_attempt_aborted_timestamp",
                    ),
                ],
            },
        ),
    ]
