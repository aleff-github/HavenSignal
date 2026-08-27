"""Static purity checks for the inert lifecycle orchestrators."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    DELETION_SOURCE_POLICY,
    FINALIZATION_SOURCE_POLICY,
    ORCHESTRATION_SOURCE_POLICIES,
    RETENTION_SOURCE_POLICY,
    OrchestrationSourceViolation,
    OrchestrationViolationCode,
    analyze_inert_orchestration_source,
    scan_inert_orchestration_sources,
)


BASE_DIR = Path(__file__).resolve().parent.parent
FINALIZATION_PATH = BASE_DIR / "report_lifecycle" / "finalization.py"
DELETION_PATH = BASE_DIR / "report_lifecycle" / "deletion.py"
RETENTION_PATH = BASE_DIR / "report_lifecycle" / "retention.py"


class CurrentInertOrchestrationSourcePolicyTests(SimpleTestCase):
    def test_current_orchestration_sources_match_the_inert_profile(self) -> None:
        violations = scan_inert_orchestration_sources(
            lifecycle_root=BASE_DIR / "report_lifecycle",
            relative_to=BASE_DIR,
        )
        self.assertEqual(violations, ())

    def test_policy_set_and_content_free_plan_fields_are_exact(self) -> None:
        self.assertEqual(
            tuple(ORCHESTRATION_SOURCE_POLICIES),
            ("deletion", "finalization", "retention"),
        )
        self.assertEqual(
            FINALIZATION_SOURCE_POLICY.relative_path,
            "report_lifecycle/finalization.py",
        )
        self.assertEqual(
            DELETION_SOURCE_POLICY.relative_path,
            "report_lifecycle/deletion.py",
        )
        self.assertEqual(
            RETENTION_SOURCE_POLICY.relative_path,
            "report_lifecycle/retention.py",
        )
        prohibited = {
            "attachment",
            "content",
            "filename",
            "key",
            "note",
            "request_body",
            "secret",
            "text",
            "verifier",
        }
        for policy in ORCHESTRATION_SOURCE_POLICIES.values():
            with self.subTest(policy=policy.name):
                field_names = {name for name, _ in policy.plan_fields}
                self.assertTrue(field_names.isdisjoint(prohibited))
                self.assertNotIn("open", policy.allowed_calls)
                self.assertNotIn("Report.objects.create", policy.allowed_calls)
                if policy is RETENTION_SOURCE_POLICY:
                    self.assertIn("timezone.now", policy.allowed_calls)
                else:
                    self.assertNotIn("timezone.now", policy.allowed_calls)
        snapshot_names = {
            name
            for _, fields, _ in RETENTION_SOURCE_POLICY.additional_dataclasses
            for name, _ in fields
        }
        self.assertTrue(snapshot_names.isdisjoint(prohibited))

    def test_policy_objects_and_registry_are_immutable(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            FINALIZATION_SOURCE_POLICY.name = "WEAKENED"
        with self.assertRaises(FrozenInstanceError):
            RETENTION_SOURCE_POLICY.name = "WEAKENED"
        with self.assertRaises(TypeError):
            ORCHESTRATION_SOURCE_POLICIES["runtime"] = FINALIZATION_SOURCE_POLICY


class InertOrchestrationSourcePolicyAbuseTests(SimpleTestCase):
    def setUp(self) -> None:
        self.finalization_source = FINALIZATION_PATH.read_text(encoding="utf-8")
        self.deletion_source = DELETION_PATH.read_text(encoding="utf-8")
        self.retention_source = RETENTION_PATH.read_text(encoding="utf-8")

    def analyze_finalization(self, source: str):
        return analyze_inert_orchestration_source(
            source=source,
            relative_path=FINALIZATION_SOURCE_POLICY.relative_path,
            policy=FINALIZATION_SOURCE_POLICY,
        )

    def analyze_deletion(self, source: str):
        return analyze_inert_orchestration_source(
            source=source,
            relative_path=DELETION_SOURCE_POLICY.relative_path,
            policy=DELETION_SOURCE_POLICY,
        )

    def analyze_retention(self, source: str):
        return analyze_inert_orchestration_source(
            source=source,
            relative_path=RETENTION_SOURCE_POLICY.relative_path,
            policy=RETENTION_SOURCE_POLICY,
        )

    def test_model_import_and_database_call_are_rejected(self) -> None:
        source = (
            "from report_lifecycle.models import Report\n"
            + self.finalization_source
            + "\nReport.objects.create()\n"
        )
        codes = {item.code for item in self.analyze_finalization(source)}
        self.assertIn(OrchestrationViolationCode.IMPORT_PROFILE_MISMATCH, codes)
        self.assertIn(OrchestrationViolationCode.CALL_DISALLOWED, codes)
        self.assertIn(OrchestrationViolationCode.MODULE_PROFILE_MISMATCH, codes)

        retention_source = (
            "from report_lifecycle.models import Report\n"
            + self.retention_source
            + "\nReport.objects.update()\n"
        )
        retention_codes = {
            item.code for item in self.analyze_retention(retention_source)
        }
        self.assertIn(
            OrchestrationViolationCode.IMPORT_PROFILE_MISMATCH,
            retention_codes,
        )
        self.assertIn(
            OrchestrationViolationCode.CALL_DISALLOWED,
            retention_codes,
        )

    def test_nested_or_star_import_cannot_bypass_the_exact_import_profile(self) -> None:
        marker = "    command, activity = _require_finalization_binding(binding)"
        sources = (
            self.finalization_source.replace(
                marker,
                f"{marker}\n    from os import environ",
                1,
            ),
            self.finalization_source.replace(
                "from .states import ReportState, SecurityOperationKind",
                "from .states import *",
                1,
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                codes = {item.code for item in self.analyze_finalization(source)}
                self.assertIn(
                    OrchestrationViolationCode.IMPORT_PROFILE_MISMATCH,
                    codes,
                )

    def test_io_network_crypto_and_authoritative_time_calls_are_rejected(self) -> None:
        calls = (
            "open('report.bin', 'wb')",
            "socket.connect()",
            "key_service.destroy()",
            "timezone.now()",
        )
        marker = "    command, activity = _require_finalization_binding(binding)"
        for call in calls:
            source = self.finalization_source.replace(
                marker,
                f"{marker}\n    {call}",
                1,
            )
            with self.subTest(call=call):
                codes = {item.code for item in self.analyze_finalization(source)}
                self.assertIn(OrchestrationViolationCode.CALL_DISALLOWED, codes)

    def test_executor_body_must_remain_the_exact_unavailable_guard(self) -> None:
        source = self.finalization_source.replace(
            "        raise FinalizationOrchestrationUnavailable()",
            "        return plan",
            1,
        )
        codes = {item.code for item in self.analyze_finalization(source)}
        self.assertIn(
            OrchestrationViolationCode.EXECUTOR_PROFILE_MISMATCH,
            codes,
        )

        retention_source = self.retention_source.replace(
            "        raise ResponseRetentionOrchestrationUnavailable()",
            "        return plan",
            1,
        )
        retention_codes = {
            item.code for item in self.analyze_retention(retention_source)
        }
        self.assertIn(
            OrchestrationViolationCode.EXECUTOR_PROFILE_MISMATCH,
            retention_codes,
        )

    def test_plan_cannot_gain_content_or_authorizing_fields(self) -> None:
        sources = (
            self.finalization_source.replace(
                "    authorizes_execution: ClassVar[bool] = False",
                "    report_text: str\n\n"
                "    authorizes_execution: ClassVar[bool] = False",
                1,
            ),
            self.deletion_source.replace(
                "    destroys_key_or_content: ClassVar[bool] = False",
                "    destroys_key_or_content: ClassVar[bool] = True",
                1,
            ),
        )
        analyzers = (self.analyze_finalization, self.analyze_deletion)
        for source, analyzer in zip(sources, analyzers):
            with self.subTest(analyzer=analyzer.__name__):
                codes = {item.code for item in analyzer(source)}
                self.assertIn(OrchestrationViolationCode.PLAN_PROFILE_MISMATCH, codes)

    def test_retention_snapshot_and_capability_profiles_are_closed(self) -> None:
        sources = (
            self.retention_source.replace(
                "    response_id: UUID",
                "    response_id: UUID\n    recovery_secret: str",
                1,
            ),
            self.retention_source.replace(
                "    decrypts_response: ClassVar[bool] = False",
                "    decrypts_response: ClassVar[bool] = True",
                1,
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                codes = {item.code for item in self.analyze_retention(source)}
                self.assertIn(
                    OrchestrationViolationCode.PLAN_PROFILE_MISMATCH,
                    codes,
                )

    def test_retention_io_crypto_logging_and_mutation_are_rejected(self) -> None:
        marker = "    observed_at = timezone.now()"
        injections = (
            "open('response.bin', 'wb')",
            "key_service.destroy()",
            "logger.info(snapshot)",
            "snapshot.response_id = UUID(int=0)",
            "match observed_at:\n        case _:\n            pass",
        )
        for injection in injections:
            source = self.retention_source.replace(
                marker,
                f"{marker}\n    {injection}",
                1,
            )
            with self.subTest(injection=injection):
                violations = self.analyze_retention(source)
                self.assertTrue(violations)
                self.assertTrue(
                    {
                        OrchestrationViolationCode.CALL_DISALLOWED,
                        OrchestrationViolationCode.DYNAMIC_CONSTRUCT,
                    }
                    & {item.code for item in violations}
                )

    def test_dynamic_flow_and_mutating_targets_are_rejected(self) -> None:
        marker = "    command, activity = _require_operator_deletion_binding(binding)"
        source = self.deletion_source.replace(
            marker,
            f"{marker}\n    global leaked_state\n"
            "    while False:\n"
            "        binding.command = None",
            1,
        )
        violations = self.analyze_deletion(source)
        self.assertIn(
            OrchestrationViolationCode.DYNAMIC_CONSTRUCT,
            {item.code for item in violations},
        )
        self.assertIn("MUTATING_TARGET", {item.detail_code for item in violations})

    def test_allowlisted_call_names_cannot_be_rebound_or_shadowed(self) -> None:
        marker = "    command, activity = _require_finalization_binding(binding)"
        sources = (
            self.finalization_source.replace(
                marker,
                f"{marker}\n    len = command.actor_id",
                1,
            ),
            self.finalization_source.replace(
                marker,
                f"{marker}\n    def timezone():\n        return command",
                1,
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                violations = self.analyze_finalization(source)
                self.assertIn(
                    OrchestrationViolationCode.DYNAMIC_CONSTRUCT,
                    {item.code for item in violations},
                )
                self.assertTrue(
                    {"CALL_NAME_REBOUND", "NESTED_DEFINITION"}
                    & {item.detail_code for item in violations}
                )

    def test_imported_types_constants_and_members_cannot_be_rebound(self) -> None:
        marker = "    observed_at = timezone.now()"
        sources = (
            self.retention_source.replace(
                marker,
                f"{marker}\n    UUID = type(validated.response_id)",
                1,
            ),
            self.retention_source.replace(
                marker,
                f"{marker}\n    UNREAD_RESPONSE_LIMIT = READ_RESPONSE_LIMIT",
                1,
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                violations = self.analyze_retention(source)
                self.assertIn(
                    "PROTECTED_NAME_REBOUND",
                    {item.detail_code for item in violations},
                )

    def test_source_is_parsed_but_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        source = f"raise RuntimeError('{sentinel}')\n" + self.deletion_source
        violations = self.analyze_deletion(source)
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        retention_source = (
            f"raise RuntimeError('{sentinel}')\n" + self.retention_source
        )
        retention_violations = self.analyze_retention(retention_source)
        self.assertTrue(retention_violations)
        self.assertNotIn(sentinel, repr(retention_violations))

    def test_parse_path_and_missing_target_fail_closed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = self.analyze_finalization(f"def broken({sentinel}\n")
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            OrchestrationViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertNotIn(sentinel, repr(violations[0]))

        outside = scan_inert_orchestration_sources(
            lifecycle_root=BASE_DIR / "report_lifecycle",
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(outside), 1)
        self.assertEqual(
            outside[0].code,
            OrchestrationViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            lifecycle = root / "report_lifecycle"
            lifecycle.mkdir()
            (lifecycle / "finalization.py").write_text(
                self.finalization_source,
                encoding="utf-8",
            )
            (lifecycle / "deletion.py").write_text(
                self.deletion_source,
                encoding="utf-8",
            )
            missing = scan_inert_orchestration_sources(
                lifecycle_root=lifecycle,
                relative_to=root,
            )
        self.assertEqual(len(missing), 1)
        self.assertEqual(
            missing[0].code,
            OrchestrationViolationCode.TARGET_SET_MISMATCH,
        )

    def test_violation_is_immutable(self) -> None:
        violation = OrchestrationSourceViolation(
            code=OrchestrationViolationCode.CALL_DISALLOWED,
            relative_path="report_lifecycle/finalization.py",
            line=1,
            detail_code="CALL_NOT_ALLOWLISTED",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 2
