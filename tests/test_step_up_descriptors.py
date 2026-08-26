"""Negative tests for inert report-bound step-up v1 components."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta

from django.test import SimpleTestCase

from security_interfaces import (
    MAX_CBOR_UINT,
    STEP_UP_PROTOCOL_VERSION,
    STEP_UP_TTL_MS,
    ReportStepUpContextV1,
    StepUpArtifactBindingPurpose,
    StepUpArtifactBindingProfileV1,
    StepUpDescriptorRejected,
    StepUpTimingV1,
    StepUpUnusedStateV1,
    WebAuthnCoseAlgorithm,
    validate_report_step_up_components_v1,
    validate_report_step_up_context_v1,
    validate_step_up_artifact_binding_profile_v1,
    validate_step_up_timing_v1,
    validate_step_up_unused_state_v1,
    validate_webauthn_cose_algorithm,
)


def make_context() -> ReportStepUpContextV1:
    return ReportStepUpContextV1(
        authorization_id=b"A" * 16,
        operator_id=b"O" * 16,
        session_id=b"S" * 16,
        report_id=b"R" * 16,
        response_id=None,
        finalization_id=None,
        lease_id=b"L" * 16,
        lease_generation=3,
        report_state_version=7,
    )


def make_artifact_profile() -> StepUpArtifactBindingProfileV1:
    return StepUpArtifactBindingProfileV1(
        purpose="STEP_UP_ARTIFACT_BINDING",
        binding_key_epoch=4,
    )


class StepUpRegistryTests(SimpleTestCase):
    def test_version_ttl_algorithms_and_purpose_are_exact(self) -> None:
        self.assertEqual(STEP_UP_PROTOCOL_VERSION, 1)
        self.assertEqual(STEP_UP_TTL_MS, 120_000)
        self.assertEqual(
            {algorithm.value for algorithm in WebAuthnCoseAlgorithm},
            {-7, -8},
        )
        self.assertEqual(
            {purpose.value for purpose in StepUpArtifactBindingPurpose},
            {"STEP_UP_ARTIFACT_BINDING"},
        )

    def test_only_es256_and_eddsa_algorithm_codes_are_accepted(self) -> None:
        self.assertEqual(
            validate_webauthn_cose_algorithm(-7),
            WebAuthnCoseAlgorithm.ES256,
        )
        self.assertEqual(
            validate_webauthn_cose_algorithm(-8),
            WebAuthnCoseAlgorithm.EDDSA,
        )
        for algorithm in (True, 0, -257, "-7"):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_webauthn_cose_algorithm(algorithm)


class ReportStepUpContextTests(SimpleTestCase):
    def test_context_fields_are_closed_and_exclude_authentication_material(self) -> None:
        names = {field.name for field in fields(ReportStepUpContextV1)}
        self.assertEqual(
            names,
            {
                "authorization_id",
                "operator_id",
                "session_id",
                "report_id",
                "response_id",
                "finalization_id",
                "lease_id",
                "lease_generation",
                "report_state_version",
            },
        )
        self.assertTrue(
            names.isdisjoint(
                {
                    "challenge",
                    "opaque_handle",
                    "credential_id",
                    "artifact_bytes",
                    "operation",
                    "report_state",
                    "artifact_kind",
                }
            )
        )

    def test_context_accepts_exact_identifier_and_counter_shapes(self) -> None:
        context = make_context()
        self.assertEqual(validate_report_step_up_context_v1(context), context)

        with_optional_ids = replace(
            context,
            response_id=b"P" * 16,
            finalization_id=b"F" * 16,
        )
        self.assertEqual(
            validate_report_step_up_context_v1(with_optional_ids),
            with_optional_ids,
        )

    def test_context_rejects_wrong_lengths_mutable_bytes_and_uints(self) -> None:
        valid = make_context()
        for context in (
            replace(valid, authorization_id=b"A" * 15),
            replace(valid, operator_id=bytearray(b"O" * 16)),
            replace(valid, session_id=b"S" * 17),
            replace(valid, report_id=b"R" * 15),
            replace(valid, response_id=b"P" * 15),
            replace(valid, finalization_id=b"F" * 17),
            replace(valid, lease_id=b"L" * 15),
            replace(valid, lease_generation=True),
            replace(valid, lease_generation=-1),
            replace(valid, report_state_version=MAX_CBOR_UINT + 1),
        ):
            with self.subTest(context=context):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_report_step_up_context_v1(context)


class StepUpArtifactAndTimingTests(SimpleTestCase):
    def test_artifact_profile_excludes_binding_and_exact_bytes(self) -> None:
        artifact_profile = make_artifact_profile()
        validated = validate_step_up_artifact_binding_profile_v1(
            artifact_profile
        )
        self.assertEqual(
            validated.purpose,
            StepUpArtifactBindingPurpose.STEP_UP_ARTIFACT_BINDING,
        )
        self.assertEqual(validated.binding_key_epoch, 4)
        self.assertEqual(
            {field.name for field in fields(StepUpArtifactBindingProfileV1)},
            {"purpose", "binding_key_epoch"},
        )
        self.assertFalse(hasattr(validated, "artifact_binding"))
        self.assertFalse(hasattr(validated, "artifact_bytes"))

        for rejected in (
            replace(artifact_profile, purpose="UNKNOWN_PURPOSE"),
            replace(artifact_profile, binding_key_epoch=True),
            replace(artifact_profile, binding_key_epoch=-1),
        ):
            with self.subTest(profile=rejected):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_step_up_artifact_binding_profile_v1(rejected)

    def test_timing_is_exactly_120_seconds_and_non_sliding(self) -> None:
        issued_at = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)
        timing = StepUpTimingV1(
            issued_at=issued_at,
            expires_at=issued_at + timedelta(milliseconds=STEP_UP_TTL_MS),
        )
        self.assertEqual(validate_step_up_timing_v1(timing), timing)

        for rejected in (
            replace(
                timing,
                expires_at=timing.expires_at - timedelta(microseconds=1),
            ),
            replace(
                timing,
                expires_at=timing.expires_at + timedelta(microseconds=1),
            ),
            StepUpTimingV1(
                issued_at=issued_at.replace(tzinfo=None),
                expires_at=timing.expires_at,
            ),
            StepUpTimingV1(
                issued_at=datetime.max.replace(tzinfo=UTC),
                expires_at=datetime.max.replace(tzinfo=UTC),
            ),
        ):
            with self.subTest(timing=rejected):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_step_up_timing_v1(rejected)

    def test_stage_a_state_can_only_represent_unused_authorization(self) -> None:
        unused = StepUpUnusedStateV1()
        self.assertEqual(validate_step_up_unused_state_v1(unused), unused)

        for state in (
            StepUpUnusedStateV1(consumed_at=1),
            StepUpUnusedStateV1(consumed_by_operation_id=b"X" * 16),
        ):
            with self.subTest(state=state):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_step_up_unused_state_v1(state)


class StepUpStructuralResultTests(SimpleTestCase):
    def test_structural_result_never_verifies_or_authorizes(self) -> None:
        issued_at = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)
        result = validate_report_step_up_components_v1(
            context=make_context(),
            artifact_profile=make_artifact_profile(),
            timing=StepUpTimingV1(
                issued_at=issued_at,
                expires_at=issued_at + timedelta(milliseconds=STEP_UP_TTL_MS),
            ),
            unused_state=StepUpUnusedStateV1(),
        )
        self.assertFalse(result.has_complete_operation_profile)
        self.assertFalse(result.verifies_webauthn)
        self.assertFalse(result.verifies_artifact_binding)
        self.assertFalse(result.authorizes_protected_action)
        self.assertFalse(hasattr(result, "challenge"))
        self.assertFalse(hasattr(result, "opaque_handle"))

    def test_descriptors_and_result_are_immutable(self) -> None:
        context = make_context()
        with self.assertRaises(FrozenInstanceError):
            context.lease_generation = 9

        issued_at = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)
        result = validate_report_step_up_components_v1(
            context=context,
            artifact_profile=make_artifact_profile(),
            timing=StepUpTimingV1(
                issued_at,
                issued_at + timedelta(milliseconds=STEP_UP_TTL_MS),
            ),
            unused_state=StepUpUnusedStateV1(),
        )
        with self.assertRaises(FrozenInstanceError):
            result.context = make_context()

    def test_unknown_value_is_not_retained_in_controlled_error(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        with self.assertRaises(StepUpDescriptorRejected) as raised:
            validate_step_up_artifact_binding_profile_v1(
                replace(make_artifact_profile(), purpose=sentinel)
            )
        self.assertEqual(str(raised.exception), "step_up_descriptor_rejected")
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
