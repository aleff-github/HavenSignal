"""Static abuse tests for the inert submission state machine source."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS,
    SubmissionSourceViolation,
    SubmissionSourceViolationCode,
    analyze_submission_source,
    scan_submission_sources,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class SubmissionSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.sources = {
            relative_path: (BASE_DIR / relative_path).read_text(encoding="utf-8")
            for relative_path in EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS
        }

    def mutate(self, relative_path: str, old: str, new: str) -> None:
        source = self.sources[relative_path]
        mutated = source.replace(old, new, 1)
        self.assertNotEqual(mutated, source)
        violations = analyze_submission_source(
            source=mutated,
            relative_path=relative_path,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            SubmissionSourceViolationCode.SOURCE_PROFILE_MISMATCH,
        )

    def test_current_sources_match_the_exact_inert_profiles(self) -> None:
        self.assertEqual(scan_submission_sources(repository_root=BASE_DIR), ())

    def test_error_and_state_registry_changes_are_rejected(self) -> None:
        mutations = (
            (
                "submission_workflow/errors.py",
                'public_code = "submission_transition_denied"',
                'public_code = "submission_transition_denied:{input}"',
            ),
            (
                "submission_workflow/states.py",
                'ABORTED = "ABORTED", "Aborted"',
                'ABORTED = "ABORTED", "Aborted"\n    REOPENED = "REOPENED", "Reopened"',
            ),
            (
                "submission_workflow/states.py",
                "SubmissionAttemptState.ACCEPTED: frozenset(),",
                "SubmissionAttemptState.ACCEPTED: "
                "frozenset({SubmissionAttemptState.READY}),",
            ),
        )
        for relative_path, old, new in mutations:
            with self.subTest(relative_path=relative_path, new=new):
                self.mutate(relative_path, old, new)

    def test_planner_capability_and_time_changes_are_rejected(self) -> None:
        relative_path = "submission_workflow/transitions.py"
        mutations = (
            (
                "target_version=current_version + 1",
                "target_version=current_version + 2",
            ),
            ("changed_at=timezone.now()", "changed_at=datetime.now()"),
            (
                "    current, target = require_allowed_transition",
                "    from django.db import transaction\n"
                "    current, target = require_allowed_transition",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.mutate(relative_path, old, new)

    def test_model_data_constraint_and_persistence_changes_are_rejected(self) -> None:
        relative_path = "submission_workflow/models.py"
        mutations = (
            (
                "    state_version = models.PositiveBigIntegerField",
                "    report_text = models.TextField()\n"
                "    state_version = models.PositiveBigIntegerField",
            ),
            (
                'name="submission_attempt_known_state"',
                'name="weakened_state_constraint"',
            ),
            (
                "            raise SubmissionTransitionDenied()\n\n"
                "        super().save",
                "            return super().save(*args, **kwargs)\n\n"
                "        super().save",
            ),
            (
                "import uuid",
                "import logging\nimport uuid",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.mutate(relative_path, old, new)

    def test_unknown_parse_and_missing_root_failures_are_controlled(self) -> None:
        unknown = analyze_submission_source(
            source="raise RuntimeError('MUST_NOT_RUN')",
            relative_path="submission_workflow/views.py",
        )
        self.assertEqual(len(unknown), 1)
        self.assertEqual(
            unknown[0].code,
            SubmissionSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_submission_source(
            source="def broken(\n",
            relative_path="submission_workflow/states.py",
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            SubmissionSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_submission_sources(
                repository_root=Path(temporary_directory),
            )
        self.assertEqual(
            len(violations),
            len(EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS),
        )
        self.assertEqual(
            {item.code for item in violations},
            {SubmissionSourceViolationCode.SOURCE_PARSE_ERROR},
        )

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        relative_path = "submission_workflow/states.py"
        violations = analyze_submission_source(
            source=self.sources[relative_path]
            + f"\nraise RuntimeError('{sentinel}')\n",
            relative_path=relative_path,
        )
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_submission_source(
            source=f"def broken({sentinel}\n",
            relative_path=relative_path,
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))

    def test_policy_and_violation_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            EXPECTED_SUBMISSION_SOURCE_AST_DIGESTS[
                "submission_workflow/models.py"
            ] = "weakened"

        violation = SubmissionSourceViolation(
            code=SubmissionSourceViolationCode.SOURCE_PROFILE_MISMATCH,
            relative_path="submission_workflow/models.py",
            line=0,
            detail_code="EXECUTABLE_AST",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 1
