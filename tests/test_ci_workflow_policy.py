"""Tests for the GitHub Actions CI workflow source policy."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks.ci_workflow import (
    CI_WORKFLOW_PATH,
    CIWorkflowViolationCode,
    analyze_ci_workflow_source,
    scan_ci_workflow_source,
    scan_repository_ci_workflow,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class CurrentCIWorkflowPolicyTests(SimpleTestCase):
    def test_current_ci_workflow_passes_source_policy(self) -> None:
        self.assertEqual(scan_repository_ci_workflow(BASE_DIR), ())


class CIWorkflowPolicyAbuseTests(SimpleTestCase):
    def test_removing_reviewed_verification_script_fails_closed(self) -> None:
        source = (BASE_DIR / CI_WORKFLOW_PATH).read_text(encoding="utf-8")
        mutated = source.replace("        run: scripts/verify\n", "")
        violations = analyze_ci_workflow_source(mutated)
        self.assertIn(
            CIWorkflowViolationCode.REQUIRED_WORKFLOW_LINE_MISSING,
            {violation.code for violation in violations},
        )

    def test_unhashed_dependency_install_is_rejected(self) -> None:
        source = (BASE_DIR / CI_WORKFLOW_PATH).read_text(encoding="utf-8")
        mutated = source.replace(
            "python -m pip install --require-hashes -r requirements.lock",
            "python -m pip install -r requirements.in",
        )
        violations = analyze_ci_workflow_source(mutated)
        self.assertIn(
            CIWorkflowViolationCode.FORBIDDEN_WORKFLOW_FRAGMENT,
            {violation.code for violation in violations},
        )

    def test_write_permissions_are_rejected_without_source_echo(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        source = (BASE_DIR / CI_WORKFLOW_PATH).read_text(encoding="utf-8")
        mutated = source.replace(
            "  contents: read\n",
            f"  contents: write # {sentinel}\n",
        )
        violations = analyze_ci_workflow_source(mutated)
        self.assertIn(
            CIWorkflowViolationCode.FORBIDDEN_WORKFLOW_FRAGMENT,
            {violation.code for violation in violations},
        )
        self.assertNotIn(sentinel, repr(violations))

    def test_unpinned_action_ref_is_rejected(self) -> None:
        source = (BASE_DIR / CI_WORKFLOW_PATH).read_text(encoding="utf-8")
        mutated = source.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@main",
        )
        violations = analyze_ci_workflow_source(mutated)
        self.assertIn(
            CIWorkflowViolationCode.FORBIDDEN_WORKFLOW_FRAGMENT,
            {violation.code for violation in violations},
        )

    def test_missing_ci_workflow_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_ci_workflow(Path(temporary_directory))
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            CIWorkflowViolationCode.SOURCE_UNAVAILABLE,
        )

    def test_out_of_root_path_fails_closed(self) -> None:
        with TemporaryDirectory() as root_dir:
            with TemporaryDirectory() as outside_dir:
                outside = Path(outside_dir) / "ci.yml"
                outside.write_text("name: CI\n", encoding="utf-8")
                violations = scan_ci_workflow_source(
                    path=outside,
                    relative_to=Path(root_dir),
                )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            CIWorkflowViolationCode.PATH_OUT_OF_ROOT,
        )
