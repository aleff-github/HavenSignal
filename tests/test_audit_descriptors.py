"""Negative and structural tests for the inert audit v1 descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    AUDIT_PROTOCOL_VERSION,
    AUTHORIZATION_WINDOWS_MS,
    CONTEXT_DEPENDENT_AUTHORIZATION_EVENTS,
    MAX_CBOR_UINT,
    AuditAcceptanceClaimsV1,
    AuditActorKind,
    AuditActorReferenceV1,
    AuditDescriptorRejected,
    AuditEventType,
    AuditReplayContextV1,
    validate_audit_acceptance_claims_v1,
    validate_audit_actor_reference_v1,
    validate_audit_replay_context_v1,
)


EXPECTED_EVENT_TYPES = {
    "SUBMISSION_ACCEPTANCE_REQUESTED",
    "SUBMISSION_RECEIVED",
    "SUBMISSION_ACCEPTANCE_FAILED",
    "CLAIM",
    "CLAIM_EXPIRED",
    "OPEN_REQUESTED",
    "OPEN_AUTHORIZED",
    "OPEN_COMPLETED",
    "OPEN_FAILED",
    "ATTACHMENT_VIEW_REQUESTED",
    "ATTACHMENT_VIEWED",
    "ATTACHMENT_VIEW_FAILED",
    "INTERRUPTED",
    "REOPEN_REQUESTED",
    "REOPEN_AUTHORIZED",
    "REOPEN_COMPLETED",
    "REOPEN_FAILED",
    "RESPONSE_RETRIEVAL_REQUESTED",
    "RESPONSE_RETRIEVAL_COMPLETED",
    "RESPONSE_RETRIEVAL_FAILED",
    "EMERGENCY_EXPORT_REQUESTED",
    "EMERGENCY_EXPORT_AUTHORIZED",
    "EMERGENCY_EXPORT_COMPLETED",
    "EMERGENCY_EXPORT_FAILED",
    "FINALIZATION_REQUESTED",
    "FINALIZATION_AUTHORIZED",
    "FINALIZATION_COMPLETED",
    "FINALIZATION_FAILED",
    "RESPONSE_AVAILABLE",
    "REPORT_KEY_DESTROYED",
    "CONTENT_DELETE_STARTED",
    "CONTENT_DELETE_COMPLETED",
    "CONTENT_DELETE_FAILED",
    "DELETE_REPORT_REQUESTED",
    "DELETE_REPORT_AUTHORIZED",
    "DELETE_REPORT_COMPLETED",
    "DELETE_REPORT_FAILED",
    "SECURITY_CONFIGURATION_CHANGED",
    "OPERATOR_AUTHENTICATION_EVENT",
    "ADMIN_AUDIT_ACCESS",
}


def make_claims(
    *,
    accepted_at_ms: int = 1_800_000_000_000,
    authorization_not_after_ms: int | None = None,
) -> AuditAcceptanceClaimsV1:
    return AuditAcceptanceClaimsV1(
        version=AUDIT_PROTOCOL_VERSION,
        log_id=b"L" * 32,
        event_id=b"E" * 16,
        leaf_index=7,
        leaf_hash=b"H" * 32,
        accepted_at_ms=accepted_at_ms,
        authorization_not_after_ms=authorization_not_after_ms,
    )


class AuditDescriptorRegistryTests(SimpleTestCase):
    def test_event_and_actor_registries_are_exactly_closed(self) -> None:
        self.assertEqual({event.value for event in AuditEventType}, EXPECTED_EVENT_TYPES)
        self.assertEqual(
            {kind.value for kind in AuditActorKind},
            {"NONE", "OPERATOR", "APPLICATION_ADMIN", "SERVICE"},
        )
        with self.assertRaises(ValueError):
            AuditEventType("REPORTER_CONTROLLED_EVENT")

    def test_authorization_windows_match_unambiguous_docs_23_rows(self) -> None:
        self.assertEqual(
            dict(AUTHORIZATION_WINDOWS_MS),
            {
                AuditEventType.SUBMISSION_ACCEPTANCE_REQUESTED: 900_000,
                AuditEventType.SUBMISSION_RECEIVED: 60_000,
                AuditEventType.OPEN_REQUESTED: 30_000,
                AuditEventType.REOPEN_REQUESTED: 30_000,
                AuditEventType.ATTACHMENT_VIEW_REQUESTED: 30_000,
                AuditEventType.RESPONSE_RETRIEVAL_REQUESTED: 30_000,
                AuditEventType.FINALIZATION_REQUESTED: 60_000,
                AuditEventType.EMERGENCY_EXPORT_REQUESTED: 60_000,
                AuditEventType.DELETE_REPORT_REQUESTED: 60_000,
            },
        )
        self.assertEqual(
            CONTEXT_DEPENDENT_AUTHORIZATION_EVENTS,
            frozenset({AuditEventType.REPORT_KEY_DESTROYED}),
        )


class AuditRequestComponentTests(SimpleTestCase):
    def test_request_component_fields_are_closed_and_content_free(self) -> None:
        self.assertEqual(
            {field.name for field in fields(AuditActorReferenceV1)},
            {"actor_kind", "actor_id"},
        )
        self.assertEqual(
            {field.name for field in fields(AuditReplayContextV1)},
            {"idempotency_id", "action_nonce"},
        )

    def test_actor_kind_and_identifier_pairing_is_exact(self) -> None:
        anonymous = validate_audit_actor_reference_v1(
            AuditActorReferenceV1(actor_kind="NONE", actor_id=None)
        )
        self.assertEqual(anonymous.actor_kind, AuditActorKind.NONE)

        operator = validate_audit_actor_reference_v1(
            AuditActorReferenceV1(actor_kind="OPERATOR", actor_id=b"A" * 16)
        )
        self.assertEqual(operator.actor_kind, AuditActorKind.OPERATOR)

        rejected = (
            AuditActorReferenceV1(actor_kind="NONE", actor_id=b"A" * 16),
            AuditActorReferenceV1(actor_kind="OPERATOR", actor_id=None),
            AuditActorReferenceV1(actor_kind="SERVICE", actor_id=b"A" * 15),
            AuditActorReferenceV1(
                actor_kind="APPLICATION_ADMIN",
                actor_id=bytearray(b"A" * 16),
            ),
            AuditActorReferenceV1(actor_kind="UNKNOWN", actor_id=None),
        )
        for reference in rejected:
            with self.subTest(reference=reference):
                with self.assertRaises(AuditDescriptorRejected):
                    validate_audit_actor_reference_v1(reference)

    def test_replay_context_accepts_only_exact_immutable_byte_lengths(self) -> None:
        valid = AuditReplayContextV1(
            idempotency_id=b"I" * 16,
            action_nonce=b"N" * 32,
        )
        self.assertEqual(validate_audit_replay_context_v1(valid), valid)

        for context in (
            replace(valid, idempotency_id=b"I" * 15),
            replace(valid, action_nonce=b"N" * 31),
            replace(valid, idempotency_id=bytearray(b"I" * 16)),
            replace(valid, action_nonce=memoryview(b"N" * 32)),
        ):
            with self.subTest(context=context):
                with self.assertRaises(AuditDescriptorRejected):
                    validate_audit_replay_context_v1(context)

    def test_request_components_are_immutable(self) -> None:
        context = AuditReplayContextV1(b"I" * 16, b"N" * 32)
        with self.assertRaises(FrozenInstanceError):
            context.action_nonce = b"X" * 32


class AuditAcceptanceClaimsTests(SimpleTestCase):
    def test_exact_authorization_window_is_structurally_accepted(self) -> None:
        accepted_at_ms = 1_800_000_000_000
        claims = make_claims(
            accepted_at_ms=accepted_at_ms,
            authorization_not_after_ms=accepted_at_ms + 30_000,
        )
        validated = validate_audit_acceptance_claims_v1(
            event_type=AuditEventType.OPEN_REQUESTED,
            claims=claims,
        )
        self.assertEqual(validated.authorization_window_ms, 30_000)
        self.assertFalse(validated.authorizes_protected_action)

    def test_non_authorizing_events_require_nil_lifetime(self) -> None:
        for event_type in AuditEventType:
            if (
                event_type in AUTHORIZATION_WINDOWS_MS
                or event_type in CONTEXT_DEPENDENT_AUTHORIZATION_EVENTS
            ):
                continue
            with self.subTest(event_type=event_type):
                validated = validate_audit_acceptance_claims_v1(
                    event_type=event_type,
                    claims=make_claims(),
                )
                self.assertIsNone(validated.authorization_window_ms)
                self.assertFalse(validated.authorizes_protected_action)

    def test_wrong_or_overflowing_lifetime_is_rejected(self) -> None:
        accepted_at_ms = 1_800_000_000_000
        for claims in (
            make_claims(
                accepted_at_ms=accepted_at_ms,
                authorization_not_after_ms=accepted_at_ms + 29_999,
            ),
            make_claims(
                accepted_at_ms=MAX_CBOR_UINT - 29_999,
                authorization_not_after_ms=MAX_CBOR_UINT,
            ),
        ):
            with self.subTest(claims=claims):
                with self.assertRaises(AuditDescriptorRejected):
                    validate_audit_acceptance_claims_v1(
                        event_type=AuditEventType.OPEN_REQUESTED,
                        claims=claims,
                    )

        with self.assertRaises(AuditDescriptorRejected):
            validate_audit_acceptance_claims_v1(
                event_type=AuditEventType.CLAIM,
                claims=make_claims(
                    accepted_at_ms=accepted_at_ms,
                    authorization_not_after_ms=accepted_at_ms + 30_000,
                ),
            )

    def test_context_dependent_report_key_event_remains_fail_closed(self) -> None:
        for lifetime in (None, 1_800_000_300_000):
            with self.subTest(lifetime=lifetime):
                with self.assertRaises(AuditDescriptorRejected):
                    validate_audit_acceptance_claims_v1(
                        event_type=AuditEventType.REPORT_KEY_DESTROYED,
                        claims=make_claims(
                            authorization_not_after_ms=lifetime,
                        ),
                    )

    def test_exact_claim_types_lengths_and_version_are_enforced(self) -> None:
        self.assertEqual(
            {field.name for field in fields(AuditAcceptanceClaimsV1)},
            {
                "version",
                "log_id",
                "event_id",
                "leaf_index",
                "leaf_hash",
                "accepted_at_ms",
                "authorization_not_after_ms",
            },
        )
        valid = make_claims()
        rejected = (
            replace(valid, version=True),
            replace(valid, version=2),
            replace(valid, log_id=b"L" * 31),
            replace(valid, event_id=b"E" * 17),
            replace(valid, leaf_index=True),
            replace(valid, leaf_index=-1),
            replace(valid, leaf_index=MAX_CBOR_UINT + 1),
            replace(valid, leaf_hash=bytearray(b"H" * 32)),
            replace(valid, accepted_at_ms=-1),
        )
        for claims in rejected:
            with self.subTest(claims=claims):
                with self.assertRaises(AuditDescriptorRejected):
                    validate_audit_acceptance_claims_v1(
                        event_type=AuditEventType.CLAIM,
                        claims=claims,
                    )

    def test_unknown_event_and_error_text_are_controlled(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        with self.assertRaises(AuditDescriptorRejected) as raised:
            validate_audit_acceptance_claims_v1(
                event_type=sentinel,
                claims=make_claims(),
            )
        self.assertEqual(str(raised.exception), "audit_descriptor_rejected")
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_structural_result_is_immutable_and_not_receipt_verification(self) -> None:
        result = validate_audit_acceptance_claims_v1(
            event_type=AuditEventType.CLAIM,
            claims=make_claims(),
        )
        with self.assertRaises(FrozenInstanceError):
            result.authorization_window_ms = 1
        self.assertFalse(result.authorizes_protected_action)
        self.assertFalse(hasattr(result, "verify_signature"))
        self.assertFalse(hasattr(result, "receipt_bytes"))
