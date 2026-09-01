"""Negative tests for inert submission credential-response descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_CREDENTIAL_RESPONSE_FORBIDDEN_PERSISTENCE_V1,
    SUBMISSION_CREDENTIAL_RESPONSE_PERMITTED_FIELDS_V1,
    SUBMISSION_CREDENTIAL_RESPONSE_PROFILE_VERSION,
    StructurallyValidSubmissionCredentialResponsePolicyV1,
    SubmissionCredentialResponseDescriptorRejected,
    SubmissionCredentialResponseForbiddenPersistence,
    SubmissionCredentialResponseOpportunity,
    SubmissionCredentialResponsePermittedField,
    SubmissionCredentialResponsePolicyV1,
    SubmissionCredentialResponseRetryResult,
    expected_submission_credential_response_policy_v1,
    validate_submission_credential_response_policy_v1,
)


class SubmissionCredentialResponseRegistryTests(SimpleTestCase):
    def test_constants_and_registries_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_CREDENTIAL_RESPONSE_PROFILE_VERSION, 1)
        self.assertEqual(
            tuple(field.value for field in SUBMISSION_CREDENTIAL_RESPONSE_PERMITTED_FIELDS_V1),
            ("TICKET_ID", "RECOVERY_SECRET"),
        )
        self.assertEqual(
            tuple(field.value for field in SUBMISSION_CREDENTIAL_RESPONSE_FORBIDDEN_PERSISTENCE_V1),
            (
                "PLAINTEXT_RECOVERY_SECRET",
                "CREDENTIAL_REDISPLAY_STATE",
                "REPLACEMENT_CREDENTIAL_STATE",
                "CREDENTIALS_DELIVERED_CLAIM",
                "CONTENT_HASH_OR_DEDUPLICATION",
                "REQUEST_HEADER",
                "RAW_ERROR",
            ),
        )

    def test_policy_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_credential_response_policy_v1(
            expected_submission_credential_response_policy_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidSubmissionCredentialResponsePolicyV1,
        )
        self.assertFalse(validated.generates_credentials)
        self.assertFalse(validated.persists_recovery_secret)
        self.assertFalse(validated.redisplays_recovery_secret)
        self.assertFalse(validated.issues_replacement_credentials)
        self.assertFalse(validated.records_credentials_delivered)
        self.assertFalse(validated.deduplicates_by_content)
        self.assertFalse(validated.creates_duplicate_report)
        self.assertFalse(validated.renders_response)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_recovery)
        self.assertFalse(validated.authorizes_submission)
        for field_name in (
            "ticket_id_value",
            "recovery_secret_value",
            "response_body",
            "request_header",
            "credentials_delivered",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionCredentialResponseValidationTests(SimpleTestCase):
    def test_policy_rejects_changed_opportunity_or_retry_result(self) -> None:
        valid = expected_submission_credential_response_policy_v1()
        self.assertEqual(
            validate_submission_credential_response_policy_v1(valid).policy,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, opportunity="ONE_LIVE_POST_ACCEPTANCE_RESPONSE"),
            replace(valid, retry_result="CONTROLLED_INDETERMINATE_OUTCOME"),
            replace(
                valid,
                opportunity=(
                    SubmissionCredentialResponseRetryResult.
                    CONTROLLED_INDETERMINATE_OUTCOME
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionCredentialResponseDescriptorRejected
                ):
                    validate_submission_credential_response_policy_v1(candidate)

    def test_policy_rejects_field_and_persistence_drift(self) -> None:
        valid = expected_submission_credential_response_policy_v1()
        for candidate in (
            replace(valid, permitted_fields=valid.permitted_fields[:-1]),
            replace(valid, permitted_fields=tuple(reversed(valid.permitted_fields))),
            replace(
                valid,
                permitted_fields=valid.permitted_fields
                + (SubmissionCredentialResponsePermittedField.TICKET_ID,),
            ),
            replace(valid, forbidden_persistence=valid.forbidden_persistence[:-1]),
            replace(
                valid,
                forbidden_persistence=tuple(
                    field.value for field in valid.forbidden_persistence
                ),
            ),
            SubmissionCredentialResponsePolicyV1(
                opportunity=(
                    SubmissionCredentialResponseOpportunity.
                    ONE_LIVE_POST_ACCEPTANCE_RESPONSE
                ),
                retry_result=(
                    SubmissionCredentialResponseRetryResult.
                    CONTROLLED_INDETERMINATE_OUTCOME
                ),
                permitted_fields=(
                    SubmissionCredentialResponseForbiddenPersistence.
                    PLAINTEXT_RECOVERY_SECRET
                ),
                forbidden_persistence=valid.forbidden_persistence,
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionCredentialResponseDescriptorRejected
                ):
                    validate_submission_credential_response_policy_v1(candidate)

    def test_policy_is_immutable_and_metadata_only(self) -> None:
        policy = expected_submission_credential_response_policy_v1()
        with self.assertRaises(FrozenInstanceError):
            policy.opportunity = "changed"

        self.assertEqual(
            {field.name for field in fields(SubmissionCredentialResponsePolicyV1)},
            {
                "opportunity",
                "retry_result",
                "permitted_fields",
                "forbidden_persistence",
            },
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_CREDENTIAL_RESPONSE_SENTINEL"
        valid = expected_submission_credential_response_policy_v1()
        with self.assertRaises(
            SubmissionCredentialResponseDescriptorRejected
        ) as raised:
            validate_submission_credential_response_policy_v1(
                replace(valid, opportunity=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "submission_credential_response_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
