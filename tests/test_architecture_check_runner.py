"""Tests for the aggregate architecture-check runner."""

import io
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks.runner import (
    ARCHITECTURE_CHECKS,
    ArchitectureCheckViolation,
    format_violation,
    main,
    run_architecture_checks,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class ArchitectureCheckRunnerTests(SimpleTestCase):
    def test_current_repository_passes_every_static_policy(self) -> None:
        self.assertEqual(run_architecture_checks(repository_root=BASE_DIR), ())

    def test_runner_registry_covers_the_reviewed_static_boundaries(self) -> None:
        self.assertEqual(
            {check.name for check in ARCHITECTURE_CHECKS},
            {
                "dependency-policy",
                "repository-hygiene",
                "verification-script",
                "ci-workflow",
                "captcha-descriptor",
                "recovery-descriptor",
                "request-admission-descriptor",
                "response-crypto-descriptor",
                "response-schema-descriptor",
                "response-text-descriptor",
                "root-url-imports",
                "reporter-gateway-imports",
                "settings-surface",
                "url-surface",
                "reporter-view-surface",
                "reporter-header-surface",
                "template-surface",
                "css-surface",
                "lifecycle-migrations",
                "submission-migrations",
                "bootstrap-sources",
                "initializer-sources",
                "submission-sources",
                "lifecycle-sources",
                "orchestration-sources",
                "negative-capabilities",
                "administrative-step-up-descriptor",
                "audit-descriptor",
                "alert-descriptor",
                "report-step-up-descriptor",
            },
        )

    def test_empty_repository_root_fails_closed_without_source_echo(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "leak.txt").write_text(sentinel, encoding="utf-8")
            violations = run_architecture_checks(repository_root=root)

        self.assertTrue(violations)
        self.assertTrue(
            all(type(item) is ArchitectureCheckViolation for item in violations)
        )
        self.assertNotIn(sentinel, repr(violations))

    def test_cli_reports_success_or_content_free_failure(self) -> None:
        success_output = io.StringIO()
        with redirect_stdout(success_output):
            success = main([str(BASE_DIR)])
        self.assertEqual(success, 0)
        self.assertEqual(success_output.getvalue(), "architecture checks passed\n")

        sentinel = "REPORT_TEXT_SENTINEL"
        failure_output = io.StringIO()
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "source.py").write_text(sentinel, encoding="utf-8")
            with redirect_stdout(failure_output):
                failure = main([str(root)])

        self.assertEqual(failure, 1)
        self.assertNotIn(sentinel, failure_output.getvalue())

    def test_violation_format_is_stable_and_content_free(self) -> None:
        formatted = format_violation(
            ArchitectureCheckViolation(
                check_name="dependency-policy",
                code="MANIFEST_HASH_MISMATCH",
                relative_path="MANIFEST.sha256",
                line=0,
                detail_code="SHA256_MISMATCH",
            )
        )
        self.assertEqual(
            formatted,
            (
                "dependency-policy MANIFEST_HASH_MISMATCH "
                "MANIFEST.sha256:0 SHA256_MISMATCH"
            ),
        )
