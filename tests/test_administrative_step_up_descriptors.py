"""Negative tests for inert administrative step-up v2 foundations."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta

from django.test import SimpleTestCase

from security_interfaces import (
    ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION,
    ADMINISTRATIVE_STEP_UP_TTL_MS,
    MAX_CBOR_UINT,
    AdministrativeStepUpArtifactProfileV2,
    AdministrativeStepUpIdentityV2,
    AdministrativeStepUpTimingV2,
    AdministrativeStepUpUnusedStateV2,
    StepUpArtifactBindingPurpose,
    StepUpDescriptorRejected,
    validate_administrative_step_up_artifact_profile_v2,
    validate_administrative_step_up_foundations_v2,
    validate_administrative_step_up_identity_v2,
    validate_administrative_step_up_timing_v2,
    validate_administrative_step_up_unused_state_v2,
)


def make_identity() -> AdministrativeStepUpIdentityV2:
    return AdministrativeStepUpIdentityV2(
        authorization_id=b"A" * 16,
        administrator_id=b"M" * 16,
        session_id=b"S" * 16,
        device_id=b"D" * 16,
    )


def make_artifact_profile() -> AdministrativeStepUpArtifactProfileV2:
    return AdministrativeStepUpArtifactProfileV2(
        purpose=StepUpArtifactBindingPurpose.STEP_UP_ARTIFACT_BINDING,
        binding_key_epoch=4,
    )


def make_timing() -> AdministrativeStepUpTimingV2:
    issued_at = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)
    return AdministrativeStepUpTimingV2(
        issued_at=issued_at,
        expires_at=issued_at
        + timedelta(milliseconds=ADMINISTRATIVE_STEP_UP_TTL_MS),
    )


class AdministrativeStepUpV2DescriptorTests(SimpleTestCase):
    def test_version_and_non_sliding_ttl_are_exact(self) -> None:
        self.assertEqual(ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION, 2)
        self.assertEqual(ADMINISTRATIVE_STEP_UP_TTL_MS, 120_000)
        self.assertEqual(
            validate_administrative_step_up_timing_v2(make_timing()),
            make_timing(),
        )

    def test_identity_fields_are_exact_and_content_free(self) -> None:
        names = {field.name for field in fields(AdministrativeStepUpIdentityV2)}
        self.assertEqual(
            names,
            {
                "authorization_id",
                "administrator_id",
                "session_id",
                "device_id",
            },
        )
        self.assertTrue(
            names.isdisjoint(
                {
                    "report_id",
                    "lease_id",
                    "ticket_id",
                    "recovery_secret",
                    "content",
                    "challenge",
                    "credential",
                    "opaque_handle",
                }
            )
        )
        identity = make_identity()
        self.assertEqual(
            validate_administrative_step_up_identity_v2(identity),
            identity,
        )

    def test_identity_rejects_wrong_or_mutable_identifier_shapes(self) -> None:
        valid = make_identity()
        rejected = (
            object(),
            replace(valid, authorization_id=b"A" * 15),
            replace(valid, administrator_id=bytearray(b"M" * 16)),
            replace(valid, session_id=b"S" * 17),
            replace(valid, device_id="device"),
        )
        for identity in rejected:
            with self.subTest(identity=identity):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_administrative_step_up_identity_v2(identity)

    def test_artifact_profile_has_no_binding_or_artifact_bytes(self) -> None:
        profile = make_artifact_profile()
        validated = validate_administrative_step_up_artifact_profile_v2(profile)
        self.assertEqual(
            validated.purpose,
            StepUpArtifactBindingPurpose.STEP_UP_ARTIFACT_BINDING,
        )
        self.assertEqual(validated.binding_key_epoch, 4)
        self.assertEqual(
            {field.name for field in fields(validated)},
            {"purpose", "binding_key_epoch"},
        )
        self.assertFalse(hasattr(validated, "artifact_binding"))
        self.assertFalse(hasattr(validated, "artifact_bytes"))

    def test_artifact_profile_rejects_unknown_purpose_and_uints(self) -> None:
        valid = make_artifact_profile()
        for profile in (
            object(),
            replace(valid, purpose="FLOOD_DELETE_NOW"),
            replace(valid, binding_key_epoch=True),
            replace(valid, binding_key_epoch=-1),
            replace(valid, binding_key_epoch=MAX_CBOR_UINT + 1),
        ):
            with self.subTest(profile=profile):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_administrative_step_up_artifact_profile_v2(profile)

    def test_timing_rejects_naive_short_long_and_overflow_values(self) -> None:
        valid = make_timing()
        rejected = (
            object(),
            replace(valid, issued_at=valid.issued_at.replace(tzinfo=None)),
            replace(valid, expires_at=valid.expires_at - timedelta(seconds=1)),
            replace(valid, expires_at=valid.expires_at + timedelta(seconds=1)),
            AdministrativeStepUpTimingV2(
                issued_at=datetime.max.replace(tzinfo=UTC),
                expires_at=datetime.max.replace(tzinfo=UTC),
            ),
        )
        for timing in rejected:
            with self.subTest(timing=timing):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_administrative_step_up_timing_v2(timing)

    def test_stage_a_state_can_only_be_unused(self) -> None:
        unused = AdministrativeStepUpUnusedStateV2()
        self.assertEqual(
            validate_administrative_step_up_unused_state_v2(unused),
            unused,
        )
        for state in (
            object(),
            AdministrativeStepUpUnusedStateV2(consumed_at=1),
            AdministrativeStepUpUnusedStateV2(
                consumed_by_operation_id=b"X" * 16
            ),
        ):
            with self.subTest(state=state):
                with self.assertRaises(StepUpDescriptorRejected):
                    validate_administrative_step_up_unused_state_v2(state)

    def test_structural_result_never_verifies_or_authorizes(self) -> None:
        result = validate_administrative_step_up_foundations_v2(
            identity=make_identity(),
            artifact_profile=make_artifact_profile(),
            timing=make_timing(),
            unused_state=AdministrativeStepUpUnusedStateV2(),
        )
        self.assertFalse(result.has_complete_operation_profile)
        self.assertFalse(result.verifies_webauthn)
        self.assertFalse(result.verifies_artifact_binding)
        self.assertFalse(result.authorizes_administrative_action)
        self.assertFalse(result.authorizes_flood_deletion)
        for absent in (
            "operation",
            "target_kind",
            "target_id",
            "artifact_kind",
            "artifact_binding",
            "webauthn_credential_row_id",
            "challenge",
            "opaque_handle",
        ):
            with self.subTest(absent=absent):
                self.assertFalse(hasattr(result, absent))

    def test_descriptors_and_result_are_immutable(self) -> None:
        identity = make_identity()
        with self.assertRaises(FrozenInstanceError):
            identity.device_id = b"X" * 16

        result = validate_administrative_step_up_foundations_v2(
            identity=identity,
            artifact_profile=make_artifact_profile(),
            timing=make_timing(),
            unused_state=AdministrativeStepUpUnusedStateV2(),
        )
        with self.assertRaises(FrozenInstanceError):
            result.identity = make_identity()

    def test_controlled_error_never_echoes_unknown_values(self) -> None:
        sentinel = "REPORT_TEXT_OR_RECOVERY_SECRET_SENTINEL"
        with self.assertRaises(StepUpDescriptorRejected) as raised:
            validate_administrative_step_up_artifact_profile_v2(
                replace(make_artifact_profile(), purpose=sentinel)
            )
        self.assertEqual(str(raised.exception), "step_up_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
