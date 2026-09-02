"""Static abuse tests for inert recovery retrieval descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_RETRIEVAL_DESCRIPTOR_PATH,
    RecoveryRetrievalDescriptorSourceViolationCode,
    analyze_recovery_retrieval_descriptor_source,
    scan_recovery_retrieval_descriptor_source,
    scan_repository_recovery_retrieval_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_RETRIEVAL_DESCRIPTOR_PATH


class RecoveryRetrievalDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_retrieval_descriptor(BASE_DIR),
            (),
        )

    def test_phase_checkpoint_and_requirement_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport requests",
            ),
            self.source.replace(
                "RECOVERY_RETRIEVAL_PROFILE_VERSION = 1",
                "RECOVERY_RETRIEVAL_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                '    ACCEPT_POST_INPUT = "ACCEPT_POST_INPUT"',
                (
                    '    ACCEPT_POST_INPUT = "ACCEPT_POST_INPUT"\n'
                    '    ACCEPT_GET_INPUT = "ACCEPT_GET_INPUT"'
                ),
            ),
            self.source.replace(
                '    KEY_SERVICE_DECRYPT_CONFIRMED = "KEY_SERVICE_DECRYPT_CONFIRMED"',
                (
                    '    KEY_SERVICE_DECRYPT_CONFIRMED = '
                    '"KEY_SERVICE_DECRYPT_OPTIONAL"'
                ),
            ),
            self.source.replace(
                '    SECRETS_NEVER_IN_URL = "SECRETS_NEVER_IN_URL"',
                '    SECRETS_NEVER_IN_URL = "SECRETS_ALLOWED_IN_URL"',
            ),
            self.source.replace(
                "sequence_index=7,\n        phase=RecoveryRetrievalPhase.APPEND_CONTENT_FREE_OUTCOME,",
                "sequence_index=7,\n        phase=RecoveryRetrievalPhase.ACCEPT_POST_INPUT,",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_retrieval_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryRetrievalDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_authorization_and_disclosure_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def handles_request(self) -> bool:\n        return False",
                "    def handles_request(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def validates_credentials(self) -> bool:\n        return False",
                "    def validates_credentials(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def appends_audit_event(self) -> bool:\n        return False",
                "    def appends_audit_event(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def calls_key_service(self) -> bool:\n        return False",
                "    def calls_key_service(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def decrypts_response(self) -> bool:\n        return False",
                "    def decrypts_response(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def renders_response(self) -> bool:\n        return False",
                "    def renders_response(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('retrieval.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda request: request\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_retrieval_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryRetrievalDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_retrieval_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryRetrievalDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_retrieval_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryRetrievalDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_retrieval_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryRetrievalDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_retrieval_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_RETRIEVAL_SENTINEL"
        violations = analyze_recovery_retrieval_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_retrieval_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
