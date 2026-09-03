"""Inert Emergency Export request-schema descriptors for version 1.

This module validates only closed schema metadata from the owner-approved
protocol. It does not hold request values, encode CBOR, normalize a protected
note, inspect report objects, create a step-up artifact, or authorize export.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import EmergencyExportRequestDescriptorRejected


EMERGENCY_EXPORT_REQUEST_PROTOCOL_VERSION = 1
EMERGENCY_EXPORT_REQUEST_PURPOSE = "EMERGENCY_EXPORT_REQUEST"
EMERGENCY_EXPORT_REQUEST_ID_BYTES = 16
EMERGENCY_EXPORT_ENVELOPE_DIGEST_BYTES = 32
EMERGENCY_EXPORT_PROTECTED_NOTE_MIN_BYTES = 1
EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_BYTES = 4_000
EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_SCALAR_VALUES = 1_000
EMERGENCY_EXPORT_OBJECT_COUNT_MIN = 1
EMERGENCY_EXPORT_OBJECT_COUNT_MAX = 5
EMERGENCY_EXPORT_OBJECT_SLOTS_V1 = (0, 1, 2, 3, 4)


class EmergencyExportRequestFieldType(StrEnum):
    UINT = "UINT"
    CONTROLLED_TEXT = "CONTROLLED_TEXT"
    BYTES = "BYTES"
    OBJECT_ARRAY = "OBJECT_ARRAY"


@dataclass(frozen=True, slots=True)
class EmergencyExportRequestFieldShapeV1:
    name: str
    field_type: EmergencyExportRequestFieldType
    exact_value: int | str | None
    exact_size_bytes: int | None
    minimum_size_bytes: int | None
    maximum_size_bytes: int | None
    allowed_uint_values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class EmergencyExportObjectOrderProfileV1:
    allowed_slots: tuple[int, ...]
    report_text_slot: int
    pdf_slot: int
    image_slot_min: int
    image_slot_max: int
    report_text_required: bool


@dataclass(frozen=True, slots=True)
class EmergencyExportRequestProfileV1:
    version: int
    purpose: str
    request_fields: tuple[EmergencyExportRequestFieldShapeV1, ...]
    object_fields: tuple[EmergencyExportRequestFieldShapeV1, ...]
    object_order: EmergencyExportObjectOrderProfileV1
    object_count_min: int
    object_count_max: int
    protected_note_max_scalar_values: int
    deterministic_cbor_required: bool
    closed_arrays_required: bool
    duplicate_fields_rejected: bool


@dataclass(frozen=True, slots=True)
class StructurallyValidEmergencyExportRequestProfileV1:
    profile: EmergencyExportRequestProfileV1

    @property
    def encodes_deterministic_cbor(self) -> bool:
        return False

    @property
    def holds_request_values(self) -> bool:
        return False

    @property
    def holds_ticket_id(self) -> bool:
        return False

    @property
    def holds_protected_note(self) -> bool:
        return False

    @property
    def holds_envelope_digests(self) -> bool:
        return False

    @property
    def creates_step_up_artifact(self) -> bool:
        return False

    @property
    def authorizes_export(self) -> bool:
        return False


def _field(
    name: str,
    field_type: EmergencyExportRequestFieldType,
    *,
    exact_value: int | str | None = None,
    exact_size_bytes: int | None = None,
    minimum_size_bytes: int | None = None,
    maximum_size_bytes: int | None = None,
    allowed_uint_values: tuple[int, ...] = (),
) -> EmergencyExportRequestFieldShapeV1:
    return EmergencyExportRequestFieldShapeV1(
        name=name,
        field_type=field_type,
        exact_value=exact_value,
        exact_size_bytes=exact_size_bytes,
        minimum_size_bytes=minimum_size_bytes,
        maximum_size_bytes=maximum_size_bytes,
        allowed_uint_values=allowed_uint_values,
    )


EMERGENCY_EXPORT_REQUEST_FIELDS_V1 = (
    _field(
        "version",
        EmergencyExportRequestFieldType.UINT,
        exact_value=EMERGENCY_EXPORT_REQUEST_PROTOCOL_VERSION,
    ),
    _field(
        "purpose",
        EmergencyExportRequestFieldType.CONTROLLED_TEXT,
        exact_value=EMERGENCY_EXPORT_REQUEST_PURPOSE,
    ),
    _field(
        "export_id",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field(
        "report_id",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field("ticket_id", EmergencyExportRequestFieldType.CONTROLLED_TEXT),
    _field(
        "report_state",
        EmergencyExportRequestFieldType.CONTROLLED_TEXT,
        exact_value="OPEN",
    ),
    _field("report_state_version", EmergencyExportRequestFieldType.UINT),
    _field(
        "lease_id",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field("lease_generation", EmergencyExportRequestFieldType.UINT),
    _field(
        "operator_id",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field(
        "session_id",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field("reason_code", EmergencyExportRequestFieldType.CONTROLLED_TEXT),
    _field(
        "protected_note",
        EmergencyExportRequestFieldType.BYTES,
        minimum_size_bytes=EMERGENCY_EXPORT_PROTECTED_NOTE_MIN_BYTES,
        maximum_size_bytes=EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_BYTES,
    ),
    _field("accepted_at", EmergencyExportRequestFieldType.CONTROLLED_TEXT),
    _field("export_time", EmergencyExportRequestFieldType.CONTROLLED_TEXT),
    _field("objects", EmergencyExportRequestFieldType.OBJECT_ARRAY),
    _field(
        "age_recipient_kid",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field(
        "manifest_signing_kid",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
)

EMERGENCY_EXPORT_OBJECT_FIELDS_V1 = (
    _field(
        "object_id",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_REQUEST_ID_BYTES,
    ),
    _field("kind", EmergencyExportRequestFieldType.CONTROLLED_TEXT),
    _field(
        "slot",
        EmergencyExportRequestFieldType.UINT,
        allowed_uint_values=EMERGENCY_EXPORT_OBJECT_SLOTS_V1,
    ),
    _field(
        "envelope_sha256",
        EmergencyExportRequestFieldType.BYTES,
        exact_size_bytes=EMERGENCY_EXPORT_ENVELOPE_DIGEST_BYTES,
    ),
)

EMERGENCY_EXPORT_OBJECT_ORDER_V1 = EmergencyExportObjectOrderProfileV1(
    allowed_slots=EMERGENCY_EXPORT_OBJECT_SLOTS_V1,
    report_text_slot=0,
    pdf_slot=1,
    image_slot_min=2,
    image_slot_max=4,
    report_text_required=True,
)


def _reject() -> Never:
    raise EmergencyExportRequestDescriptorRejected()


def _require_field_sequence(value: object) -> None:
    if type(value) is not tuple:
        _reject()
    for field in value:
        if (
            type(field) is not EmergencyExportRequestFieldShapeV1
            or type(field.name) is not str
            or type(field.field_type) is not EmergencyExportRequestFieldType
            or (
                field.exact_value is not None
                and type(field.exact_value) not in (int, str)
            )
            or (
                field.exact_size_bytes is not None
                and type(field.exact_size_bytes) is not int
            )
            or (
                field.minimum_size_bytes is not None
                and type(field.minimum_size_bytes) is not int
            )
            or (
                field.maximum_size_bytes is not None
                and type(field.maximum_size_bytes) is not int
            )
            or type(field.allowed_uint_values) is not tuple
            or any(type(item) is not int for item in field.allowed_uint_values)
        ):
            _reject()


def expected_emergency_export_request_profile_v1(
) -> EmergencyExportRequestProfileV1:
    return EmergencyExportRequestProfileV1(
        version=EMERGENCY_EXPORT_REQUEST_PROTOCOL_VERSION,
        purpose=EMERGENCY_EXPORT_REQUEST_PURPOSE,
        request_fields=EMERGENCY_EXPORT_REQUEST_FIELDS_V1,
        object_fields=EMERGENCY_EXPORT_OBJECT_FIELDS_V1,
        object_order=EMERGENCY_EXPORT_OBJECT_ORDER_V1,
        object_count_min=EMERGENCY_EXPORT_OBJECT_COUNT_MIN,
        object_count_max=EMERGENCY_EXPORT_OBJECT_COUNT_MAX,
        protected_note_max_scalar_values=(
            EMERGENCY_EXPORT_PROTECTED_NOTE_MAX_SCALAR_VALUES
        ),
        deterministic_cbor_required=True,
        closed_arrays_required=True,
        duplicate_fields_rejected=True,
    )


def validate_emergency_export_request_profile_v1(
    profile: EmergencyExportRequestProfileV1,
) -> StructurallyValidEmergencyExportRequestProfileV1:
    if type(profile) is not EmergencyExportRequestProfileV1:
        _reject()
    _require_field_sequence(profile.request_fields)
    _require_field_sequence(profile.object_fields)
    if (
        type(profile.version) is not int
        or type(profile.purpose) is not str
        or type(profile.object_count_min) is not int
        or type(profile.object_count_max) is not int
        or type(profile.protected_note_max_scalar_values) is not int
        or type(profile.object_order) is not EmergencyExportObjectOrderProfileV1
        or type(profile.object_order.allowed_slots) is not tuple
        or any(
            type(slot) is not int for slot in profile.object_order.allowed_slots
        )
        or type(profile.object_order.report_text_slot) is not int
        or type(profile.object_order.pdf_slot) is not int
        or type(profile.object_order.image_slot_min) is not int
        or type(profile.object_order.image_slot_max) is not int
        or type(profile.object_order.report_text_required) is not bool
        or type(profile.deterministic_cbor_required) is not bool
        or type(profile.closed_arrays_required) is not bool
        or type(profile.duplicate_fields_rejected) is not bool
        or profile != expected_emergency_export_request_profile_v1()
    ):
        _reject()
    return StructurallyValidEmergencyExportRequestProfileV1(
        profile=expected_emergency_export_request_profile_v1()
    )
