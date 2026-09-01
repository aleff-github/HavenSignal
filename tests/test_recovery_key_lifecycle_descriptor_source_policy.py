"""Static abuse tests for inert recovery key lifecycle descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_KEY_LIFECYCLE_DESCRIPTOR_PATH,
    RecoveryKeyLifecycleDescriptorSourceViolationCode,
    analyze_recovery_key_lifecycle_descriptor_source,
    scan_recovery_key_lifecycle_descriptor_source,
    scan_repository_recovery_key_lifecycle_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_KEY_LIFECYCLE_DESCRIPTOR_PATH


class RecoveryKeyLifecycleDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_key_lifecycle_descriptor(BASE_DIR),
            (),
        )

    def test_import_size_state_separation_location_and_requirement_changes_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hmac",
            ),
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport secrets",
            ),
            self.source.replace(
                "RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION = 1",
                "RECOVERY_KEY_LIFECYCLE_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                "RECOVERY_VERIFIER_KEY_BYTES = 32",
                "RECOVERY_VERIFIER_KEY_BYTES = 16",
            ),
            self.source.replace(
                '    RETIRED_VERIFY_ONLY = "RETIRED_VERIFY_ONLY"',
                (
                    '    RETIRED_VERIFY_ONLY = "RETIRED_VERIFY_ONLY"\n'
                    '    ACTIVE_FOR_ALL_REQUESTS = "ACTIVE_FOR_ALL_REQUESTS"'
                ),
            ),
            self.source.replace(
                '    RESPONSE_DEK = "RESPONSE_DEK"',
                (
                    '    RESPONSE_DEK = "RESPONSE_DEK"\n'
                    '    REPORTER_SECRET = "REPORTER_SECRET"'
                ),
            ),
            self.source.replace(
                '    APPLICATION_DATABASE = "APPLICATION_DATABASE"',
                (
                    '    APPLICATION_DATABASE = "APPLICATION_DATABASE"\n'
                    '    CLOUD_BACKUP = "CLOUD_BACKUP"'
                ),
            ),
            self.source.replace(
                '    LOSS_FAILS_CLOSED = "LOSS_FAILS_CLOSED"',
                (
                    '    LOSS_FAILS_CLOSED = "LOSS_FAILS_CLOSED"\n'
                    '    LOCAL_FALLBACK = "LOCAL_FALLBACK"'
                ),
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_key_lifecycle_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryKeyLifecycleDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def generates_key(self) -> bool:\n        return False",
                "    def generates_key(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def stores_key(self) -> bool:\n        return False",
                "    def stores_key(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def rotates_key(self) -> bool:\n        return False",
                "    def rotates_key(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def calls_key_service(self) -> bool:\n        return False",
                "    def calls_key_service(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_response_dek_use(self) -> bool:\n        return False",
                "    def authorizes_response_dek_use(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_recovery(self) -> bool:\n        return False",
                "    def authorizes_recovery(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('recovery-key.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda key_id: key_id\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_key_lifecycle_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryKeyLifecycleDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_key_lifecycle_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryKeyLifecycleDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_key_lifecycle_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryKeyLifecycleDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_key_lifecycle_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryKeyLifecycleDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_key_lifecycle_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_KEY_LIFECYCLE_SENTINEL"
        violations = analyze_recovery_key_lifecycle_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_key_lifecycle_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
