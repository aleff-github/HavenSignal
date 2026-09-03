"""Static abuse tests for the inert report-lifecycle core source."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS,
    LifecycleSourceViolation,
    LifecycleSourceViolationCode,
    analyze_lifecycle_source,
    scan_lifecycle_sources,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class LifecycleSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.sources = {
            relative_path: (BASE_DIR / relative_path).read_text(encoding="utf-8")
            for relative_path in EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS
        }

    def mutate(self, relative_path: str, old: str, new: str) -> None:
        source = self.sources[relative_path]
        mutated = source.replace(old, new, 1)
        self.assertNotEqual(mutated, source)
        violations = analyze_lifecycle_source(
            source=mutated,
            relative_path=relative_path,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            LifecycleSourceViolationCode.SOURCE_PROFILE_MISMATCH,
        )

    def test_current_sources_match_the_exact_inert_profiles(self) -> None:
        self.assertEqual(scan_lifecycle_sources(repository_root=BASE_DIR), ())

    def test_error_state_and_transition_changes_are_rejected(self) -> None:
        mutations = (
            (
                "report_lifecycle/errors.py",
                'super().__init__("lifecycle_transition_denied")',
                'super().__init__(f"lifecycle_transition_denied:{input}")',
            ),
            (
                "report_lifecycle/states.py",
                'DESTROYED = "DESTROYED", "Destroyed"',
                'DESTROYED = "DESTROYED", "Destroyed"\n'
                '    RESTORED = "RESTORED", "Restored"',
            ),
            (
                "report_lifecycle/states.py",
                "ReportState.DESTROYED: frozenset(),",
                "ReportState.DESTROYED: frozenset({ReportState.OPEN}),",
            ),
            (
                "report_lifecycle/transitions.py",
                "LEASE_IDLE_LIMIT = timedelta(minutes=5)",
                "LEASE_IDLE_LIMIT = timedelta(minutes=10)",
            ),
            (
                "report_lifecycle/transitions.py",
                "target_version=version + 1",
                "target_version=version + 2",
            ),
        )
        for relative_path, old, new in mutations:
            with self.subTest(relative_path=relative_path, new=new):
                self.mutate(relative_path, old, new)

    def test_binding_fence_and_authority_changes_are_rejected(self) -> None:
        relative_path = "report_lifecycle/bindings.py"
        mutations = (
            (
                "requires_active_lease=True",
                "requires_active_lease=False",
            ),
            (
                "or command_generation != lease_generation",
                "or False",
            ),
            (
                "report_state != policy.required_report_state",
                "False",
            ),
            (
                "validated_at = timezone.now()",
                "validated_at = datetime.now()",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.mutate(relative_path, old, new)

    def test_model_schema_constraint_and_mutation_changes_are_rejected(self) -> None:
        relative_path = "report_lifecycle/models.py"
        mutations = (
            (
                "    state_version = models.PositiveBigIntegerField",
                "    report_text = models.TextField()\n"
                "    state_version = models.PositiveBigIntegerField",
            ),
            (
                'name="one_active_lease_per_report"',
                'name="weakened_active_lease_constraint"',
            ),
            (
                "            raise LifecycleTransitionDenied()\n"
                "        super().save(*args, **kwargs)",
                "            return super().save(*args, **kwargs)\n"
                "        super().save(*args, **kwargs)",
            ),
            (
                "import uuid",
                "import logging\nimport uuid",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.mutate(relative_path, old, new)

    def test_persistence_locking_activation_and_backend_weakening_are_rejected(
        self,
    ) -> None:
        relative_path = "report_lifecycle/persistence.py"
        mutations = (
            (
                'capabilities.vendor != "postgresql"',
                'capabilities.vendor not in {"postgresql", "sqlite"}',
            ),
            (
                ".select_for_update()",
                ".all()",
            ),
            (
                "with transaction.atomic(using=using):",
                "if True:",
            ),
            (
                "maximum_fence + 1",
                "maximum_fence",
            ),
            (
                "and operation.fence_token == prepared.fence_token",
                "and True",
            ),
            (
                "target_state=SecurityOperationState.ACTIVE",
                "target_state=SecurityOperationState.ABORTED",
            ),
            (
                "activated_at=transition.changed_at",
                "activated_at=None",
            ),
            (
                "target_state=SecurityOperationState.ABORTED",
                "target_state=SecurityOperationState.COMPLETED",
            ),
            (
                "terminal_at=transition.changed_at",
                "terminal_at=None",
            ),
            (
                "type(operation_id) is not UUID",
                "not isinstance(operation_id, UUID)",
            ),
            (
                "if not _is_prepared_operation(operation):",
                "if False:",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.mutate(relative_path, old, new)

    def test_unknown_parse_and_missing_root_failures_are_controlled(self) -> None:
        unknown = analyze_lifecycle_source(
            source="raise RuntimeError('MUST_NOT_RUN')",
            relative_path="report_lifecycle/views.py",
        )
        self.assertEqual(len(unknown), 1)
        self.assertEqual(
            unknown[0].code,
            LifecycleSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_lifecycle_source(
            source="def broken(\n",
            relative_path="report_lifecycle/states.py",
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            LifecycleSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_lifecycle_sources(
                repository_root=Path(temporary_directory),
            )
        self.assertEqual(
            len(violations),
            len(EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS),
        )
        self.assertEqual(
            {item.code for item in violations},
            {LifecycleSourceViolationCode.SOURCE_PARSE_ERROR},
        )

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        relative_path = "report_lifecycle/bindings.py"
        violations = analyze_lifecycle_source(
            source=self.sources[relative_path]
            + f"\nraise RuntimeError('{sentinel}')\n",
            relative_path=relative_path,
        )
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_lifecycle_source(
            source=f"def broken({sentinel}\n",
            relative_path=relative_path,
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))

    def test_policy_and_violation_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            EXPECTED_LIFECYCLE_SOURCE_AST_DIGESTS[
                "report_lifecycle/models.py"
            ] = "weakened"

        violation = LifecycleSourceViolation(
            code=LifecycleSourceViolationCode.SOURCE_PROFILE_MISMATCH,
            relative_path="report_lifecycle/models.py",
            line=0,
            detail_code="EXECUTABLE_AST",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 1
