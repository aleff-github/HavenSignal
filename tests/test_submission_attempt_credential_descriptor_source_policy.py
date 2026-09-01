"""Static abuse tests for inert submission-attempt credential descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_PATH,
    SubmissionAttemptCredentialDescriptorSourceViolationCode,
    analyze_submission_attempt_credential_descriptor_source,
    scan_repository_submission_attempt_credential_descriptor,
    scan_submission_attempt_credential_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / SUBMISSION_ATTEMPT_CREDENTIAL_DESCRIPTOR_PATH


class SubmissionAttemptCredentialDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_submission_attempt_credential_descriptor(BASE_DIR),
            (),
        )

    def test_import_timing_transport_and_binding_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport secrets",
            ),
            self.source.replace(
                "SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION = 1",
                "SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                "SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS = 2 * 60 * 60 * 1000",
                "SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS = 3 * 60 * 60 * 1000",
            ),
            self.source.replace(
                '    URL = "URL"',
                '    URL = "URL"\n    LOCAL_STORAGE = "LOCAL_STORAGE"',
            ),
            self.source.replace(
                '    IP_ADDRESS = "IP_ADDRESS"',
                '    IP_ADDRESS = "IP_ADDRESS"\n    EMAIL = "EMAIL"',
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = (
                    analyze_submission_attempt_credential_descriptor_source(
                        source=source
                    )
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionAttemptCredentialDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_generation_logging_endpoint_and_authorization_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    def generates_credential(self) -> bool:\n        return False",
                "    def generates_credential(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def verifies_credential(self) -> bool:\n        return False",
                "    def verifies_credential(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def logs_credential(self) -> bool:\n        return False",
                "    def logs_credential(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def exposes_endpoint(self) -> bool:\n        return False",
                "    def exposes_endpoint(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('attempt.txt', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda credential: credential\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = (
                    analyze_submission_attempt_credential_descriptor_source(
                        source=source
                    )
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionAttemptCredentialDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_submission_attempt_credential_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            (
                SubmissionAttemptCredentialDescriptorSourceViolationCode.
                TARGET_SET_MISMATCH
            ),
        )

        parse_failure = analyze_submission_attempt_credential_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            (
                SubmissionAttemptCredentialDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR
            ),
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_submission_attempt_credential_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            (
                SubmissionAttemptCredentialDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR
            ),
        )

        violations = scan_submission_attempt_credential_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "SUBMISSION_ATTEMPT_CREDENTIAL_SENTINEL"
        violations = analyze_submission_attempt_credential_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_submission_attempt_credential_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
