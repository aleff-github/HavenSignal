"""Negative tests for inert recovery retrieval descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1,
    RECOVERY_RETRIEVAL_CHECKPOINTS_V1,
    RECOVERY_RETRIEVAL_FORBIDDEN_CAPABILITIES_V1,
    RECOVERY_RETRIEVAL_PHASES_V1,
    RECOVERY_RETRIEVAL_PROFILE_VERSION,
    RecoveryRetrievalCheckpoint,
    RecoveryRetrievalCheckpointDescriptorV1,
    RecoveryRetrievalDescriptorRejected,
    RecoveryRetrievalForbiddenCapability,
    RecoveryRetrievalPhase,
    RecoveryRetrievalProfileV1,
    RecoveryRetrievalRequirement,
    StructurallyValidRecoveryRetrievalProfileV1,
    expected_recovery_retrieval_profile_v1,
    validate_recovery_retrieval_checkpoint_descriptor_v1,
    validate_recovery_retrieval_profile_v1,
)


class RecoveryRetrievalRegistryTests(SimpleTestCase):
    def test_version_phase_and_checkpoint_order_are_exact(self) -> None:
        self.assertEqual(RECOVERY_RETRIEVAL_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in RECOVERY_RETRIEVAL_PHASES_V1),
            (
                "ACCEPT_POST_INPUT",
                "VALIDATE_CHALLENGE_AND_CREDENTIALS",
                "OBTAIN_RETRIEVAL_AUDIT_RECEIPT",
                "LOCK_AND_VALIDATE_ELIGIBILITY",
                "ARM_OR_CONVERT_RESPONSE_EXPIRY",
                "DECRYPT_WITH_SCOPED_AUTHORIZATION",
                "VALIDATE_AND_RENDER_CANONICAL_TEXT",
                "APPEND_CONTENT_FREE_OUTCOME",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in RECOVERY_RETRIEVAL_CHECKPOINTS_V1),
            (
                "POST_ONLY_INPUT_RECEIVED",
                "CAPTCHA_AND_VERIFIER_APPROVED",
                "RESPONSE_RETRIEVAL_REQUESTED_RECEIPT_DURABLE",
                "SERVER_STATE_AND_VERSION_LOCKED",
                "IMMUTABLE_EXPIRY_CONFIRMED",
                "KEY_SERVICE_DECRYPT_CONFIRMED",
                "CANONICAL_TEXT_READY_WITH_NO_STORE",
                "CONTENT_FREE_OUTCOME_APPENDED",
            ),
        )
        self.assertEqual(
            tuple(
                item.value for item in RECOVERY_RETRIEVAL_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "HANDLES_REQUEST",
                "VALIDATES_CAPTCHA",
                "VALIDATES_CREDENTIALS",
                "APPENDS_AUDIT_EVENT",
                "VERIFIES_AUDIT_RECEIPT",
                "QUERIES_RESPONSE_STATE",
                "MUTATES_FIRST_READ",
                "CALLS_KEY_SERVICE",
                "DECRYPTS_RESPONSE",
                "VALIDATES_PLAINTEXT_FRAME",
                "RENDERS_RESPONSE",
                "PERSISTS_PLAINTEXT",
                "LOGS_CREDENTIALS_OR_PLAINTEXT",
                "RETURNS_DISTINCT_FAILURE",
                "EXPOSES_ENDPOINT",
                "AUTHORIZES_RECOVERY",
            ),
        )

    def test_checkpoint_descriptors_are_exact(self) -> None:
        self.assertEqual(
            tuple(
                item.sequence_index
                for item in RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1
            ),
            tuple(range(8)),
        )
        self.assertEqual(
            tuple(item.phase for item in RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1),
            RECOVERY_RETRIEVAL_PHASES_V1,
        )
        self.assertEqual(
            tuple(
                item.checkpoint
                for item in RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1
            ),
            RECOVERY_RETRIEVAL_CHECKPOINTS_V1,
        )
        decrypt = RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1[5]
        self.assertIn(
            RecoveryRetrievalRequirement.RECOVERY_SECRET_NOT_SENT_TO_KEY_SERVICE,
            decrypt.requirements,
        )
        self.assertIn(
            RecoveryRetrievalRequirement.KEY_SERVICE_EXPIRY_MATCH_REQUIRED,
            decrypt.requirements,
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_recovery_retrieval_profile_v1(
            expected_recovery_retrieval_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidRecoveryRetrievalProfileV1,
        )
        self.assertFalse(validated.handles_request)
        self.assertFalse(validated.validates_captcha)
        self.assertFalse(validated.validates_credentials)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.verifies_audit_receipt)
        self.assertFalse(validated.queries_response_state)
        self.assertFalse(validated.mutates_first_read)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.decrypts_response)
        self.assertFalse(validated.validates_plaintext_frame)
        self.assertFalse(validated.renders_response)
        self.assertFalse(validated.persists_plaintext)
        self.assertFalse(validated.logs_credentials_or_plaintext)
        self.assertFalse(validated.returns_distinct_failure)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        for field_name in (
            "request",
            "ticket_id",
            "recovery_secret",
            "captcha_answer",
            "receipt",
            "state_row",
            "response_dek",
            "plaintext",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class RecoveryRetrievalValidationTests(SimpleTestCase):
    def test_checkpoint_descriptor_rejects_drift(self) -> None:
        valid = RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1[0]
        self.assertEqual(
            validate_recovery_retrieval_checkpoint_descriptor_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, sequence_index=1),
            replace(valid, sequence_index=True),
            replace(valid, sequence_index=-1),
            replace(
                valid,
                phase=RecoveryRetrievalPhase.LOCK_AND_VALIDATE_ELIGIBILITY,
            ),
            replace(
                valid,
                checkpoint=RecoveryRetrievalCheckpoint.KEY_SERVICE_DECRYPT_CONFIRMED,
            ),
            replace(valid, requirements=valid.requirements[:-1]),
            RecoveryRetrievalCheckpointDescriptorV1(
                sequence_index=0,
                phase=RecoveryRetrievalPhase.ACCEPT_POST_INPUT,
                checkpoint=RecoveryRetrievalCheckpoint.POST_ONLY_INPUT_RECEIVED,
                requirements=(
                    RecoveryRetrievalForbiddenCapability.EXPOSES_ENDPOINT,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryRetrievalDescriptorRejected):
                    validate_recovery_retrieval_checkpoint_descriptor_v1(
                        candidate
                    )

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_recovery_retrieval_profile_v1()
        self.assertEqual(validate_recovery_retrieval_profile_v1(valid).profile, valid)
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, scheme_version=True),
            replace(valid, checkpoints=valid.checkpoints[:-1]),
            replace(valid, checkpoints=tuple(reversed(valid.checkpoints))),
            replace(
                valid,
                forbidden_capabilities=valid.forbidden_capabilities[:-1],
            ),
            RecoveryRetrievalProfileV1(
                scheme_version=1,
                checkpoints=list(valid.checkpoints),  # type: ignore[arg-type]
                forbidden_capabilities=valid.forbidden_capabilities,
            ),
            RecoveryRetrievalProfileV1(
                scheme_version=1,
                checkpoints=valid.checkpoints,
                forbidden_capabilities=(
                    RecoveryRetrievalForbiddenCapability.AUTHORIZES_RECOVERY,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RecoveryRetrievalDescriptorRejected):
                    validate_recovery_retrieval_profile_v1(candidate)  # type: ignore[arg-type]

    def test_profiles_are_frozen_and_slot_limited(self) -> None:
        profiles = (
            RECOVERY_RETRIEVAL_CHECKPOINT_DESCRIPTORS_V1[0],
            expected_recovery_retrieval_profile_v1(),
        )
        for profile in profiles:
            with self.subTest(profile=type(profile).__name__):
                self.assertFalse(hasattr(profile, "__dict__"))
                first_field = fields(profile)[0].name
                with self.assertRaises(FrozenInstanceError):
                    setattr(profile, first_field, object())
