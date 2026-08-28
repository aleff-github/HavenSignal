"""Tests for fail-closed dependency and integrity policy checks."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks.dependency_policy import (
    DependencyPolicyViolationCode,
    analyze_dependabot_source,
    analyze_django_sources,
    analyze_manifest,
    scan_repository,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class CurrentDependencyPolicyTests(SimpleTestCase):
    def test_current_repository_passes_dependency_policy(self) -> None:
        self.assertEqual(scan_repository(BASE_DIR), ())


class DependabotPolicyAbuseTests(SimpleTestCase):
    def test_routine_version_updates_are_rejected(self) -> None:
        source = """version: 2
updates:
  - package-ecosystem: pip
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    open-pull-requests-limit: 0
"""
        violations = analyze_dependabot_source(source)
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.DEPENDABOT_VERSION_UPDATES_ENABLED,
        )
        self.assertEqual(violations[0].detail_code, "PIP")

    def test_missing_security_monitored_ecosystem_is_rejected(self) -> None:
        source = """version: 2
updates:
  - package-ecosystem: pip
    open-pull-requests-limit: 0
"""
        violations = analyze_dependabot_source(source)
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.DEPENDABOT_ECOSYSTEM_INVALID,
        )
        self.assertEqual(violations[0].detail_code, "GITHUB_ACTIONS")

    def test_new_ecosystem_cannot_reenable_routine_updates(self) -> None:
        source = """version: 2
updates:
  - package-ecosystem: pip
    open-pull-requests-limit: 0
  - package-ecosystem: github-actions
    open-pull-requests-limit: 0
  - package-ecosystem: docker
    open-pull-requests-limit: 1
"""
        violations = analyze_dependabot_source(source)
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.DEPENDABOT_VERSION_UPDATES_ENABLED,
        )
        self.assertEqual(violations[0].detail_code, "DOCKER")


class DjangoPinPolicyAbuseTests(SimpleTestCase):
    def test_feature_release_outside_approved_lts_line_is_rejected(self) -> None:
        violations = analyze_django_sources(
            declared_source="Django==6.1.0\n",
            locked_source="Django==6.1.0 \\\n+    --hash=sha256:00\n",
        )
        self.assertEqual(len(violations), 2)
        self.assertTrue(
            all(
                violation.code
                == DependencyPolicyViolationCode.DJANGO_SERIES_UNAPPROVED
                for violation in violations
            )
        )

    def test_changed_declaration_without_regenerated_lock_is_rejected(self) -> None:
        violations = analyze_django_sources(
            declared_source="Django==5.2.18\n",
            locked_source="Django==5.2.17 \\\n+    --hash=sha256:00\n",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.DJANGO_LOCK_MISMATCH,
        )

    def test_range_or_unpinned_declaration_is_rejected(self) -> None:
        violations = analyze_django_sources(
            declared_source="Django>=5.2\n",
            locked_source="Django==5.2.17 \\\n+    --hash=sha256:00\n",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.DJANGO_DECLARATION_INVALID,
        )


class ManifestPolicyAbuseTests(SimpleTestCase):
    def _analyze(
        self,
        *,
        payload: bytes = b"reviewed\n",
        digest: str | None = None,
        tracked_paths: tuple[str, ...] = ("MANIFEST.sha256", "reviewed.txt"),
    ):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "reviewed.txt").write_bytes(payload)
            expected = digest or hashlib.sha256(payload).hexdigest()
            return analyze_manifest(
                root=root,
                source=f"{expected}  reviewed.txt\n",
                tracked_paths=tracked_paths,
            )

    def test_exact_manifest_passes(self) -> None:
        self.assertEqual(self._analyze(), ())

    def test_hash_mismatch_is_rejected_without_exposing_bytes(self) -> None:
        sentinel = b"REPORT_TEXT_SENTINEL"
        violations = self._analyze(payload=sentinel, digest="0" * 64)
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.MANIFEST_HASH_MISMATCH,
        )
        self.assertNotIn(sentinel.decode("ascii"), repr(violations[0]))

    def test_unlisted_tracked_file_is_rejected(self) -> None:
        violations = self._analyze(
            tracked_paths=(
                "MANIFEST.sha256",
                "reviewed.txt",
                "missing-from-manifest.txt",
            )
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.MANIFEST_COVERAGE_MISMATCH,
        )

    def test_parent_path_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            violations = analyze_manifest(
                root=Path(temporary_directory),
                source=f"{'0' * 64}  ../outside.txt\n",
                tracked_paths=("MANIFEST.sha256",),
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.MANIFEST_FORMAT_INVALID,
        )

    def test_windows_style_parent_path_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            violations = analyze_manifest(
                root=Path(temporary_directory),
                source=f"{'0' * 64}  ..\\outside.txt\n",
                tracked_paths=("MANIFEST.sha256",),
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            DependencyPolicyViolationCode.MANIFEST_FORMAT_INVALID,
        )
