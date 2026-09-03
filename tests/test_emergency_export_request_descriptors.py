"""Negative tests for inert Emergency Export request-schema metadata."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    EMERGENCY_EXPORT_ENVELOPE_DIGEST_BYTES,
    EMERGENCY_EXPORT_OBJECT_COUNT_MAX,
    EMERGENCY_EXPORT_OBJECT_COUNT_MIN,
    EMERGENCY_EXPORT_OBJECT_FIELDS_V1,
    EMERGENCY_EXPORT_OBJECT_ORDER_V1,
    EMERGENCY_EXPORT_OBJECT_SLOTS_V1,
    EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_BYTES,
    EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_SCALAR_VALUES,
    EMERGENCY_EXPORT_PROTECTED_NOTE_MIN_BYTES,
    EMERGENCY_EXPORT_REQUEST_FIELDS_V1,
    EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    EMERGENCY_EXPORT_REQUEST_PROTOCOL_VERSION,
    EMERGENCY_EXPORT_REQUEST_PURPOSE,
    EmergencyExportRequestFieldShapeV1,
    EmergencyExportRequestFieldType,
    EmergencyExportRequestDescriptorRejected,
    EmergencyExportRequestProfileV1,
    StructurallyValidEmergencyExportRequestProfileV1,
    expected_emergency_export_request_profile_v1,
    validate_emergency_export_request_profile_v1,
)


class EmergencyExportRequestDescriptorTests(SimpleTestCase):
    def test_constants_and_closed_field_order_match_the_approved_protocol(
        self,
    ) -> None:
        self.assertEqual(EMERGENCY_EXPORT_REQUEST_PROTOCOL_VERSION, 1)
        self.assertEqual(
            EMERGENCY_EXPORT_REQUEST_PURPOSE,
            "EMERGENCY_EXPORT_REQUEST",
        )
        self.assertEqual(EMERGENCY_EXPORT_REQUEST_ID_BYTES, 16)
        self.assertEqual(EMERGENCY_EXPORT_ENVELOPE_DIGEST_BYTES, 32)
        self.assertEqual(EMERGENCY_EXPORT_PROTECTED_NOTE_MIN_BYTES, 1)
        self.assertEqual(EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_BYTES, 4_000)
        self.assertEqual(
            EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_SCALAR_VALUES,
            1_000,
        )
        self.assertEqual(EMERGENCY_EXPORT_OBJECT_COUNT_MIN, 1)
        self.assertEqual(EMERGENCY_EXPORT_OBJECT_COUNT_MAX, 5)
        self.assertEqual(EMERGENCY_EXPORT_OBJECT_SLOTS_V1, (0, 1, 2, 3, 4))
        self.assertEqual(
            tuple(field.name for field in EMERGENCY_EXPORT_REQUEST_FIELDS_V1),
            (
                "version",
                "purpose",
                "export_id",
                "report_id",
                "ticket_id",
                "report_state",
                "report_state_version",
                "lease_id",
                "lease_generation",
                "operator_id",
                "session_id",
                "reason_code",
                "protected_note",
                "accepted_at",
                "export_time",
                "objects",
                "age_recipient_kid",
                "manifest_signing_kid",
            ),
        )
        self.assertEqual(
            tuple(field.name for field in EMERGENCY_EXPORT_OBJECT_FIELDS_V1),
            ("object_id", "kind", "slot", "envelope_sha256"),
        )

    def test_expected_profile_is_structural_and_non_authorizing(self) -> None:
        expected = expected_emergency_export_request_profile_v1()
        validated = validate_emergency_export_request_profile_v1(expected)
        self.assertIs(
            type(validated),
            StructurallyValidEmergencyExportRequestProfileV1,
        )
        self.assertEqual(validated.profile, expected)
        self.assertFalse(validated.encodes_deterministic_cbor)
        self.assertFalse(validated.holds_request_values)
        self.assertFalse(validated.holds_ticket_id)
        self.assertFalse(validated.holds_protected_note)
        self.assertFalse(validated.holds_envelope_digests)
        self.assertFalse(validated.creates_step_up_artifact)
        self.assertFalse(validated.authorizes_export)
        self.assertEqual(
            {field.name for field in fields(validated)},
            {"profile"},
        )
        for forbidden in (
            "ticket_id",
            "protected_note",
            "envelope_sha256",
            "artifact_bytes",
            "recipient_key",
            "signing_key",
            "report_content",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(hasattr(validated, forbidden))

    def test_field_shapes_fix_sizes_ranges_and_ordering_only(self) -> None:
        request_fields = {
            field.name: field for field in EMERGENCY_EXPORT_REQUEST_FIELDS_V1
        }
        self.assertEqual(request_fields["version"].exact_value, 1)
        self.assertEqual(
            request_fields["purpose"].exact_value,
            "EMERGENCY_EXPORT_REQUEST",
        )
        self.assertEqual(request_fields["report_state"].exact_value, "OPEN")
        for field_name in (
            "export_id",
            "report_id",
            "lease_id",
            "operator_id",
            "session_id",
            "age_recipient_kid",
            "manifest_signing_kid",
        ):
            self.assertEqual(
                request_fields[field_name].exact_size_bytes,
                EMERGENCY_EXPORT_REQUEST_ID_BYTES,
            )
        protected_note = request_fields["protected_note"]
        self.assertEqual(
            protected_note.minimum_size_bytes,
            EMERGENCY_EXPORT_PROTECTED_NOTE_MIN_BYTES,
        )
        self.assertEqual(
            protected_note.maximum_size_bytes,
            EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_BYTES,
        )
        object_fields = {
            field.name: field for field in EMERGENCY_EXPORT_OBJECT_FIELDS_V1
        }
        self.assertEqual(
            object_fields["slot"].allowed_uint_values,
            EMERGENCY_EXPORT_OBJECT_SLOTS_V1,
        )
        self.assertEqual(
            object_fields["envelope_sha256"].exact_size_bytes,
            EMERGENCY_EXPORT_ENVELOPE_DIGEST_BYTES,
        )
        self.assertEqual(
            EMERGENCY_EXPORT_OBJECT_ORDER_V1.allowed_slots,
            EMERGENCY_EXPORT_OBJECT_SLOTS_V1,
        )
        self.assertTrue(EMERGENCY_EXPORT_OBJECT_ORDER_V1.report_text_required)

    def test_profile_rejects_top_level_and_nested_drift(self) -> None:
        valid = expected_emergency_export_request_profile_v1()
        changed_field = replace(
            EMERGENCY_EXPORT_REQUEST_FIELDS_V1[0],
            exact_value=2,
        )
        candidates = (
            object(),
            replace(valid, version=True),
            replace(valid, purpose="EXPORT"),
            replace(valid, request_fields=list(valid.request_fields)),
            replace(valid, request_fields=(changed_field,) + valid.request_fields[1:]),
            replace(valid, object_fields=valid.object_fields[:-1]),
            replace(
                valid,
                object_order=replace(
                    valid.object_order,
                    report_text_required=False,
                ),
            ),
            replace(valid, object_count_min=0),
            replace(valid, object_count_max=6),
            replace(valid, protected_note_max_scalar_values=1_001),
            replace(valid, deterministic_cbor_required=False),
            replace(valid, closed_arrays_required=False),
            replace(valid, duplicate_fields_rejected=False),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    EmergencyExportRequestDescriptorRejected
                ):
                    validate_emergency_export_request_profile_v1(candidate)

    def test_nested_field_instances_and_profile_are_immutable(self) -> None:
        field = EMERGENCY_EXPORT_REQUEST_FIELDS_V1[0]
        self.assertIs(type(field), EmergencyExportRequestFieldShapeV1)
        self.assertIs(
            type(field.field_type),
            EmergencyExportRequestFieldType,
        )
        with self.assertRaises(FrozenInstanceError):
            field.name = "changed"
        profile = expected_emergency_export_request_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.version = 2

    def test_rejection_is_controlled_and_content_free(self) -> None:
        sentinel = "PROTECTED_NOTE_SENTINEL"
        invalid = EmergencyExportRequestProfileV1(
            version=1,
            purpose=sentinel,
            request_fields=EMERGENCY_EXPORT_REQUEST_FIELDS_V1,
            object_fields=EMERGENCY_EXPORT_OBJECT_FIELDS_V1,
            object_order=EMERGENCY_EXPORT_OBJECT_ORDER_V1,
            object_count_min=1,
            object_count_max=5,
            protected_note_max_scalar_values=1_000,
            deterministic_cbor_required=True,
            closed_arrays_required=True,
            duplicate_fields_rejected=True,
        )
        with self.assertRaises(EmergencyExportRequestDescriptorRejected) as raised:
            validate_emergency_export_request_profile_v1(invalid)
        self.assertEqual(
            str(raised.exception),
            "emergency_export_request_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
