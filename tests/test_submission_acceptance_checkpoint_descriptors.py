"""Negative tests for inert submission-acceptance checkpoint descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1,
    SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION,
    SUBMISSION_ACCEPTANCE_CHECKPOINTS_V1,
    SUBMISSION_ACCEPTANCE_FORBIDDEN_CAPABILITIES_V1,
    SUBMISSION_ACCEPTANCE_PHASES_V1,
    StructurallyValidSubmissionAcceptanceCheckpointProfileV1,
    SubmissionAcceptanceCheckpoint,
    SubmissionAcceptanceCheckpointDescriptorRejected,
    SubmissionAcceptanceCheckpointDescriptorV1,
    SubmissionAcceptanceCheckpointProfileV1,
    SubmissionAcceptanceForbiddenCapability,
    SubmissionAcceptancePhase,
    SubmissionAcceptanceRequirement,
    expected_submission_acceptance_checkpoint_profile_v1,
    validate_submission_acceptance_checkpoint_descriptor_v1,
    validate_submission_acceptance_checkpoint_profile_v1,
)


class SubmissionAcceptanceCheckpointRegistryTests(SimpleTestCase):
    def test_version_phase_and_checkpoint_order_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_ACCEPTANCE_PHASES_V1),
            (
                "SERVE_INERT_FORM",
                "ADMIT_REQUEST",
                "VALIDATE_TRANSIENT_INPUT",
                "OBTAIN_PRE_ACTION_AUDIT_EVIDENCE",
                "PROTECT_AND_STAGE",
                "AUDIT_AND_COMMIT_ACCEPTANCE",
                "RECONCILE_WITHOUT_PLAINTEXT",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in SUBMISSION_ACCEPTANCE_CHECKPOINTS_V1),
            (
                "FORM_SURFACE_READY",
                "ATTEMPT_CLAIMED_BEFORE_PIPELINE",
                "TRANSIENT_INPUT_VALIDATED",
                "REQUESTED_RECEIPT_DURABLE_BEFORE_KEY_OR_CONTENT",
                "CIPHERTEXT_AND_METADATA_STAGED_NON_VISIBLE",
                "RECEIVED_RECEIPT_BOUND_TO_SEALED_COMMIT",
                "NONTERMINAL_ATTEMPT_FINISHED_OR_ABORTED",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in SUBMISSION_ACCEPTANCE_FORBIDDEN_CAPABILITIES_V1
            ),
            (
                "REQUEST_PARSING",
                "CREDENTIAL_VALIDATION",
                "ATTEMPT_CLAIMING",
                "AUDIT_APPEND",
                "RECEIPT_VERIFICATION",
                "KEY_SERVICE_CALL",
                "ENCRYPTION",
                "STORAGE_WRITE",
                "DATABASE_COMMIT",
                "RESPONSE_RENDERING",
                "RECONCILER_EXECUTION",
                "ENDPOINT_EXPOSURE",
                "SUBMISSION_AUTHORIZATION",
            ),
        )

    def test_checkpoint_descriptors_are_exact(self) -> None:
        self.assertEqual(
            tuple(item.sequence_index for item in SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1),
            tuple(range(7)),
        )
        self.assertEqual(
            tuple(item.phase for item in SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1),
            SUBMISSION_ACCEPTANCE_PHASES_V1,
        )
        self.assertEqual(
            tuple(item.checkpoint for item in SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1),
            SUBMISSION_ACCEPTANCE_CHECKPOINTS_V1,
        )
        requested = SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1[3]
        self.assertIn(
            SubmissionAcceptanceRequirement.REQUESTED_RECEIPT_DURABLE,
            requested.requirements,
        )
        self.assertIn(
            SubmissionAcceptanceRequirement.REQUESTED_RECEIPT_CONTEXT_VALID,
            requested.requirements,
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_acceptance_checkpoint_profile_v1(
            expected_submission_acceptance_checkpoint_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidSubmissionAcceptanceCheckpointProfileV1,
        )
        self.assertFalse(validated.parses_request)
        self.assertFalse(validated.validates_credential)
        self.assertFalse(validated.claims_attempt)
        self.assertFalse(validated.appends_audit_event)
        self.assertFalse(validated.verifies_receipt)
        self.assertFalse(validated.calls_key_service)
        self.assertFalse(validated.encrypts_content)
        self.assertFalse(validated.persists_records)
        self.assertFalse(validated.renders_response)
        self.assertFalse(validated.reconciles_attempts)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_submission)
        for field_name in (
            "request",
            "credential",
            "receipt",
            "report_text",
            "plaintext",
            "database_row",
            "response_body",
            "endpoint",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionAcceptanceCheckpointValidationTests(SimpleTestCase):
    def test_checkpoint_descriptor_rejects_drift(self) -> None:
        valid = SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTORS_V1[0]
        self.assertEqual(
            validate_submission_acceptance_checkpoint_descriptor_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, sequence_index=1),
            replace(valid, sequence_index=True),
            replace(valid, phase=SubmissionAcceptancePhase.ADMIT_REQUEST),
            replace(
                valid,
                checkpoint=SubmissionAcceptanceCheckpoint.TRANSIENT_INPUT_VALIDATED,
            ),
            replace(valid, requirements=valid.requirements[:-1]),
            SubmissionAcceptanceCheckpointDescriptorV1(
                sequence_index=0,
                phase=SubmissionAcceptancePhase.SERVE_INERT_FORM,
                checkpoint=SubmissionAcceptanceCheckpoint.FORM_SURFACE_READY,
                requirements=(
                    SubmissionAcceptanceForbiddenCapability.ENDPOINT_EXPOSURE,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAcceptanceCheckpointDescriptorRejected
                ):
                    validate_submission_acceptance_checkpoint_descriptor_v1(
                        candidate
                    )

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_submission_acceptance_checkpoint_profile_v1()
        self.assertEqual(
            validate_submission_acceptance_checkpoint_profile_v1(valid).profile,
            valid,
        )
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
            replace(
                valid,
                forbidden_capabilities=tuple(
                    reversed(valid.forbidden_capabilities)
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAcceptanceCheckpointDescriptorRejected
                ):
                    validate_submission_acceptance_checkpoint_profile_v1(
                        candidate
                    )

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        profile = expected_submission_acceptance_checkpoint_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        self.assertEqual(
            {field.name for field in fields(SubmissionAcceptanceCheckpointProfileV1)},
            {"scheme_version", "checkpoints", "forbidden_capabilities"},
        )
        self.assertEqual(
            {
                field.name
                for field in fields(SubmissionAcceptanceCheckpointDescriptorV1)
            },
            {"sequence_index", "phase", "checkpoint", "requirements"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_ACCEPTANCE_CHECKPOINT_SENTINEL"
        valid = expected_submission_acceptance_checkpoint_profile_v1()
        with self.assertRaises(
            SubmissionAcceptanceCheckpointDescriptorRejected
        ) as raised:
            validate_submission_acceptance_checkpoint_profile_v1(
                replace(valid, scheme_version=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "submission_acceptance_checkpoint_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
