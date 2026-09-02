"""State, abuse, and persistence tests for submission acceptance metadata."""

from pathlib import Path

from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from anonymous_reporting import urls
from submission_workflow.errors import SubmissionTransitionDenied
from submission_workflow.models import SubmissionAttempt
from submission_workflow.states import (
    ALLOWED_TRANSITIONS,
    SubmissionAttemptState,
    require_allowed_transition,
)
from submission_workflow.transitions import MAX_STATE_VERSION, plan_submission_transition


class SubmissionTransitionPolicyTests(SimpleTestCase):
    def test_every_documented_edge_is_allowed(self) -> None:
        expected = {
            (SubmissionAttemptState.READY, SubmissionAttemptState.PROCESSING),
            (
                SubmissionAttemptState.PROCESSING,
                SubmissionAttemptState.CIPHERTEXT_STAGED,
            ),
            (
                SubmissionAttemptState.CIPHERTEXT_STAGED,
                SubmissionAttemptState.AUDIT_CONFIRMED,
            ),
            (
                SubmissionAttemptState.AUDIT_CONFIRMED,
                SubmissionAttemptState.ACCEPTED,
            ),
            (SubmissionAttemptState.READY, SubmissionAttemptState.ABORTING),
            (SubmissionAttemptState.PROCESSING, SubmissionAttemptState.ABORTING),
            (
                SubmissionAttemptState.CIPHERTEXT_STAGED,
                SubmissionAttemptState.ABORTING,
            ),
            (
                SubmissionAttemptState.AUDIT_CONFIRMED,
                SubmissionAttemptState.ABORTING,
            ),
            (SubmissionAttemptState.ABORTING, SubmissionAttemptState.ABORTED),
        }
        actual = {
            (source, target)
            for source, targets in ALLOWED_TRANSITIONS.items()
            for target in targets
        }
        self.assertEqual(actual, expected)

        for source, target in expected:
            with self.subTest(source=source, target=target):
                self.assertEqual(require_allowed_transition(source, target), (source, target))

    def test_every_other_edge_fails_closed(self) -> None:
        for source in SubmissionAttemptState:
            for target in SubmissionAttemptState:
                if target in ALLOWED_TRANSITIONS[source]:
                    continue
                with self.subTest(source=source, target=target):
                    with self.assertRaises(SubmissionTransitionDenied) as raised:
                        require_allowed_transition(source, target)
                    self.assertEqual(str(raised.exception), "submission_transition_denied")

    def test_unknown_state_fails_with_the_same_controlled_error(self) -> None:
        for source, target in (
            ("UNKNOWN", SubmissionAttemptState.PROCESSING),
            (SubmissionAttemptState.READY, "UNKNOWN"),
        ):
            with self.subTest(source=source, target=target):
                with self.assertRaises(SubmissionTransitionDenied) as raised:
                    require_allowed_transition(source, target)
                self.assertEqual(str(raised.exception), "submission_transition_denied")

    def test_planner_increments_exactly_one_version_and_uses_server_time(self) -> None:
        attempt = SubmissionAttempt()
        before = timezone.now()
        plan = plan_submission_transition(
            attempt_id=attempt.id,
            current_state=SubmissionAttemptState.READY,
            current_version=7,
            target_state=SubmissionAttemptState.PROCESSING,
        )
        after = timezone.now()

        self.assertEqual(plan.current_version, 7)
        self.assertEqual(plan.target_version, 8)
        self.assertLessEqual(before, plan.changed_at)
        self.assertLessEqual(plan.changed_at, after)

    def test_planner_rejects_invalid_versions(self) -> None:
        attempt = SubmissionAttempt()
        for version in (-1, True, 1.5, "1", MAX_STATE_VERSION):
            with self.subTest(version=version):
                with self.assertRaises(SubmissionTransitionDenied) as raised:
                    plan_submission_transition(
                        attempt_id=attempt.id,
                        current_state=SubmissionAttemptState.READY,
                        current_version=version,
                        target_state=SubmissionAttemptState.PROCESSING,
                    )
                self.assertEqual(str(raised.exception), "submission_transition_denied")

    def test_planner_rejects_a_non_uuid_internal_identifier(self) -> None:
        with self.assertRaises(SubmissionTransitionDenied) as raised:
            plan_submission_transition(
                attempt_id="browser-controlled-value",
                current_state=SubmissionAttemptState.READY,
                current_version=0,
                target_state=SubmissionAttemptState.PROCESSING,
            )
        self.assertEqual(str(raised.exception), "submission_transition_denied")


class SubmissionAttemptPersistenceTests(TestCase):
    def test_new_attempt_contains_only_internal_metadata(self) -> None:
        before = timezone.now()
        attempt = SubmissionAttempt.objects.create()
        after = timezone.now()

        self.assertEqual(attempt.state, SubmissionAttemptState.READY)
        self.assertEqual(attempt.state_version, 0)
        self.assertLessEqual(before, attempt.created_at)
        self.assertLessEqual(attempt.created_at, after)
        self.assertLessEqual(attempt.created_at, attempt.last_progress_at)
        self.assertLessEqual(attempt.last_progress_at, after)

        field_names = {field.name for field in SubmissionAttempt._meta.fields}
        forbidden_fragments = {
            "attachment",
            "body",
            "content",
            "credential",
            "dek",
            "filename",
            "header",
            "ip",
            "key",
            "recovery",
            "report",
            "secret",
            "ticket",
            "user_agent",
            "verifier",
        }
        for field_name in field_names:
            with self.subTest(field=field_name):
                self.assertFalse(
                    any(fragment in field_name.lower() for fragment in forbidden_fragments)
                )

    def test_happy_path_policy_increments_one_version_per_edge(self) -> None:
        attempt = SubmissionAttempt.objects.create()
        path = (
            SubmissionAttemptState.PROCESSING,
            SubmissionAttemptState.CIPHERTEXT_STAGED,
            SubmissionAttemptState.AUDIT_CONFIRMED,
            SubmissionAttemptState.ACCEPTED,
        )

        current_state = SubmissionAttemptState.READY
        current_version = 0
        for expected_version, target in enumerate(path):
            plan = plan_submission_transition(
                attempt_id=attempt.id,
                current_state=current_state,
                current_version=current_version,
                target_state=target,
            )
            self.assertEqual(plan.target_state, target)
            self.assertEqual(plan.target_version, expected_version + 1)
            current_state = plan.target_state
            current_version = plan.target_version

        # Planning cannot persist ACCEPTED without the still-gated audit and
        # cryptographic dependencies.
        attempt.refresh_from_db()
        self.assertEqual(attempt.state, SubmissionAttemptState.READY)
        self.assertEqual(attempt.state_version, 0)
        self.assertIsNone(attempt.accepted_at)
        self.assertIsNone(attempt.aborting_at)
        self.assertIsNone(attempt.aborted_at)

    def test_direct_mutation_through_save_is_denied(self) -> None:
        attempt = SubmissionAttempt.objects.create()
        attempt.state = SubmissionAttemptState.PROCESSING
        with self.assertRaises(SubmissionTransitionDenied):
            attempt.save()

    def test_creation_in_any_state_other_than_ready_is_denied(self) -> None:
        with self.assertRaises(SubmissionTransitionDenied):
            SubmissionAttempt.objects.create(
                state=SubmissionAttemptState.PROCESSING,
                state_version=1,
            )

    def test_database_rejects_unknown_state_and_missing_terminal_timestamp(self) -> None:
        attempt = SubmissionAttempt.objects.create()
        invalid_updates = (
            {"state": "UNKNOWN"},
            {"state": SubmissionAttemptState.PROCESSING},
            {"state": SubmissionAttemptState.ACCEPTED},
            {"state": SubmissionAttemptState.ABORTING},
        )
        for updates in invalid_updates:
            with self.subTest(updates=updates):
                with self.assertRaises(IntegrityError):
                    with transaction.atomic():
                        SubmissionAttempt.objects.filter(id=attempt.id).update(**updates)

    def test_no_accepting_submission_route_or_view_is_enabled(self) -> None:
        self.assertEqual(
            {pattern.name for pattern in urls.urlpatterns},
            {
                "reporter-home",
                "reporter-status",
                "reporter-submit",
                "reporter-response",
                "operator-console",
            },
        )
        app_path = Path(SubmissionAttempt._meta.app_config.path)
        self.assertFalse((app_path / "views.py").exists())
