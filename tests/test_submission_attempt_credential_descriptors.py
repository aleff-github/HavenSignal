"""Negative tests for inert submission-attempt credential descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SUBMISSION_ATTEMPT_CREDENTIAL_ALLOWED_TRANSPORTS_V1,
    SUBMISSION_ATTEMPT_CREDENTIAL_DURABLE_REPRESENTATIONS_V1,
    SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_BINDINGS_V1,
    SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_PERSISTENCE_V1,
    SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_TRANSPORTS_V1,
    SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS,
    SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION,
    StructurallyValidSubmissionAttemptCredentialProfileV1,
    SubmissionAttemptCredentialAllowedTransport,
    SubmissionAttemptCredentialBindingProfileV1,
    SubmissionAttemptCredentialDescriptorRejected,
    SubmissionAttemptCredentialDurableRepresentation,
    SubmissionAttemptCredentialExpiry,
    SubmissionAttemptCredentialForbiddenBinding,
    SubmissionAttemptCredentialForbiddenPersistence,
    SubmissionAttemptCredentialForbiddenTransport,
    SubmissionAttemptCredentialLifetimeProfileV1,
    SubmissionAttemptCredentialPersistenceProfileV1,
    SubmissionAttemptCredentialProfileV1,
    SubmissionAttemptCredentialTransportProfileV1,
    SubmissionAttemptCredentialUse,
    expected_submission_attempt_credential_profile_v1,
    validate_submission_attempt_credential_binding_profile_v1,
    validate_submission_attempt_credential_lifetime_profile_v1,
    validate_submission_attempt_credential_persistence_profile_v1,
    validate_submission_attempt_credential_profile_v1,
    validate_submission_attempt_credential_transport_profile_v1,
)


class SubmissionAttemptCredentialRegistryTests(SimpleTestCase):
    def test_timing_and_registries_are_exact(self) -> None:
        self.assertEqual(SUBMISSION_ATTEMPT_CREDENTIAL_PROFILE_VERSION, 1)
        self.assertEqual(
            SUBMISSION_ATTEMPT_CREDENTIAL_PRE_CLAIM_TTL_MS,
            2 * 60 * 60 * 1000,
        )
        self.assertEqual(
            tuple(
                item.value
                for item in SUBMISSION_ATTEMPT_CREDENTIAL_ALLOWED_TRANSPORTS_V1
            ),
            ("POST_BODY", "PROTECTED_SAME_SITE_COOKIE"),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_TRANSPORTS_V1
            ),
            ("URL", "QUERY_STRING", "HEADER_LOG", "REFERRER"),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_BINDINGS_V1
            ),
            (
                "REPORT_CONTENT",
                "TICKET_ID",
                "RECOVERY_SECRET",
                "IP_ADDRESS",
                "USER_AGENT",
                "REPORTER_ACCOUNT",
                "DEVICE_FINGERPRINT",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in (
                    SUBMISSION_ATTEMPT_CREDENTIAL_DURABLE_REPRESENTATIONS_V1
                )
            ),
            (
                "MINIMUM_VERIFIER_INDEX",
                "DATABASE_UNIQUENESS_CONSTRAINT",
                "ROW_STATE_VERSION_CHECK",
            ),
        )
        self.assertEqual(
            tuple(
                item.value
                for item in SUBMISSION_ATTEMPT_CREDENTIAL_FORBIDDEN_PERSISTENCE_V1
            ),
            (
                "PLAINTEXT_CREDENTIAL",
                "APPLICATION_LOG",
                "AUDIT_LOG",
                "REQUEST_BODY_LOG",
                "REQUEST_HEADER_LOG",
                "REPORTER_METADATA",
            ),
        )

    def test_profile_is_metadata_only_and_non_authorizing(self) -> None:
        validated = validate_submission_attempt_credential_profile_v1(
            expected_submission_attempt_credential_profile_v1()
        )
        self.assertIsInstance(
            validated,
            StructurallyValidSubmissionAttemptCredentialProfileV1,
        )
        self.assertFalse(validated.generates_credential)
        self.assertFalse(validated.verifies_credential)
        self.assertFalse(validated.persists_plaintext_credential)
        self.assertFalse(validated.installs_cookie)
        self.assertFalse(validated.inspects_request)
        self.assertFalse(validated.claims_attempt)
        self.assertFalse(validated.logs_credential)
        self.assertFalse(validated.writes_credential_to_audit)
        self.assertFalse(validated.binds_to_reporter_identity)
        self.assertFalse(validated.binds_to_network_metadata)
        self.assertFalse(validated.creates_reporter_account)
        self.assertFalse(validated.exposes_endpoint)
        self.assertFalse(validated.authorizes_submission)
        self.assertFalse(validated.authorizes_report_read)
        for field_name in (
            "credential",
            "credential_text",
            "verifier",
            "cookie_value",
            "ip_address",
            "user_agent",
            "report_text",
            "ticket_id",
            "recovery_secret",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SubmissionAttemptCredentialValidationTests(SimpleTestCase):
    def test_lifetime_profile_rejects_drift(self) -> None:
        valid = expected_submission_attempt_credential_profile_v1().lifetime
        self.assertEqual(
            validate_submission_attempt_credential_lifetime_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, use="SINGLE_USE"),
            replace(valid, expiry="NON_SLIDING_PRE_CLAIM"),
            replace(valid, pre_claim_ttl_ms=7_200_001),
            replace(valid, pre_claim_ttl_ms=True),
            replace(valid, use=SubmissionAttemptCredentialExpiry.NON_SLIDING_PRE_CLAIM),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAttemptCredentialDescriptorRejected
                ):
                    validate_submission_attempt_credential_lifetime_profile_v1(
                        candidate
                    )

    def test_transport_profile_rejects_drift(self) -> None:
        valid = expected_submission_attempt_credential_profile_v1().transport
        self.assertEqual(
            validate_submission_attempt_credential_transport_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, allowed_transports=valid.allowed_transports[:-1]),
            replace(
                valid,
                allowed_transports=tuple(reversed(valid.allowed_transports)),
            ),
            replace(
                valid,
                allowed_transports=valid.allowed_transports
                + (SubmissionAttemptCredentialAllowedTransport.POST_BODY,),
            ),
            replace(valid, forbidden_transports=valid.forbidden_transports[:-1]),
            SubmissionAttemptCredentialTransportProfileV1(
                allowed_transports=(
                    SubmissionAttemptCredentialForbiddenTransport.URL,
                ),
                forbidden_transports=valid.forbidden_transports,
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAttemptCredentialDescriptorRejected
                ):
                    validate_submission_attempt_credential_transport_profile_v1(
                        candidate
                    )

    def test_binding_profile_rejects_drift(self) -> None:
        valid = expected_submission_attempt_credential_profile_v1().binding
        self.assertEqual(
            validate_submission_attempt_credential_binding_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(valid, forbidden_bindings=valid.forbidden_bindings[:-1]),
            replace(
                valid,
                forbidden_bindings=tuple(reversed(valid.forbidden_bindings)),
            ),
            SubmissionAttemptCredentialBindingProfileV1(
                forbidden_bindings=(
                    SubmissionAttemptCredentialAllowedTransport.POST_BODY,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAttemptCredentialDescriptorRejected
                ):
                    validate_submission_attempt_credential_binding_profile_v1(
                        candidate
                    )

    def test_persistence_profile_rejects_drift(self) -> None:
        valid = expected_submission_attempt_credential_profile_v1().persistence
        self.assertEqual(
            validate_submission_attempt_credential_persistence_profile_v1(valid),
            valid,
        )
        for candidate in (
            object(),
            replace(
                valid,
                durable_representations=valid.durable_representations[:-1],
            ),
            replace(
                valid,
                durable_representations=tuple(
                    reversed(valid.durable_representations)
                ),
            ),
            replace(valid, forbidden_persistence=valid.forbidden_persistence[:-1]),
            SubmissionAttemptCredentialPersistenceProfileV1(
                durable_representations=(
                    SubmissionAttemptCredentialDurableRepresentation.
                    MINIMUM_VERIFIER_INDEX
                ),
                forbidden_persistence=(
                    SubmissionAttemptCredentialForbiddenPersistence.
                    PLAINTEXT_CREDENTIAL
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAttemptCredentialDescriptorRejected
                ):
                    validate_submission_attempt_credential_persistence_profile_v1(
                        candidate
                    )

    def test_profile_rejects_changed_parts(self) -> None:
        valid = expected_submission_attempt_credential_profile_v1()
        self.assertEqual(
            validate_submission_attempt_credential_profile_v1(valid).profile,
            valid,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, lifetime=object()),
            replace(valid, transport=object()),
            replace(valid, binding=object()),
            replace(valid, persistence=object()),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    SubmissionAttemptCredentialDescriptorRejected
                ):
                    validate_submission_attempt_credential_profile_v1(candidate)

    def test_descriptors_are_immutable_and_metadata_only(self) -> None:
        lifetime = expected_submission_attempt_credential_profile_v1().lifetime
        with self.assertRaises(FrozenInstanceError):
            lifetime.pre_claim_ttl_ms = 1

        self.assertEqual(
            {field.name for field in fields(SubmissionAttemptCredentialProfileV1)},
            {"scheme_version", "lifetime", "transport", "binding", "persistence"},
        )
        self.assertEqual(
            {
                field.name
                for field in fields(SubmissionAttemptCredentialLifetimeProfileV1)
            },
            {"use", "expiry", "pre_claim_ttl_ms"},
        )

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SUBMISSION_ATTEMPT_CREDENTIAL_SENTINEL"
        valid = expected_submission_attempt_credential_profile_v1().lifetime
        with self.assertRaises(
            SubmissionAttemptCredentialDescriptorRejected
        ) as raised:
            validate_submission_attempt_credential_lifetime_profile_v1(
                replace(valid, use=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "submission_attempt_credential_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
