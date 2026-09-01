"""Inert submission-audit phase descriptors from the approved docs/20 flow.

This module validates only static phase and payload-policy metadata. It does
not append audit events, create receipts, verify receipts, inspect attempts,
call services, persist metadata, create report keys, or authorize submission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .audit_descriptors import AuditEventType
from .errors import SubmissionAuditDescriptorRejected


SUBMISSION_AUDIT_PROFILE_VERSION = 1
SUBMISSION_AUDIT_REQUESTED_AUTHORIZATION_WINDOW_MS = 15 * 60 * 1000
SUBMISSION_AUDIT_RECEIVED_AUTHORIZATION_WINDOW_MS = 60 * 1000
SUBMISSION_AUDIT_FAILED_AUTHORIZATION_WINDOW_MS = 0


class SubmissionAuditPhase(StrEnum):
    ACCEPTANCE_REQUESTED = "ACCEPTANCE_REQUESTED"
    RECEIVED = "RECEIVED"
    ACCEPTANCE_FAILED = "ACCEPTANCE_FAILED"


class SubmissionAuditTiming(StrEnum):
    BEFORE_KEY_OR_MATERIAL_CREATION = "BEFORE_KEY_OR_MATERIAL_CREATION"
    AFTER_STAGED_CIPHERTEXT_DURABILITY = "AFTER_STAGED_CIPHERTEXT_DURABILITY"
    BEST_EFFORT_ABORT_EVIDENCE = "BEST_EFFORT_ABORT_EVIDENCE"


class SubmissionAuditAllowedPayloadField(StrEnum):
    SYSTEM_GENERATED_IDENTIFIER = "SYSTEM_GENERATED_IDENTIFIER"
    EVENT_OPERATION_CODE = "EVENT_OPERATION_CODE"
    ATTEMPT_STATE = "ATTEMPT_STATE"
    ATTEMPT_VERSION = "ATTEMPT_VERSION"
    CALLER_IDENTITY = "CALLER_IDENTITY"
    IDEMPOTENCY_CONTEXT = "IDEMPOTENCY_CONTEXT"
    ANTI_REPLAY_CONTEXT = "ANTI_REPLAY_CONTEXT"


class SubmissionAuditForbiddenPayloadField(StrEnum):
    REPORT_TEXT = "REPORT_TEXT"
    ATTACHMENT_CONTENT = "ATTACHMENT_CONTENT"
    ORIGINAL_FILENAME = "ORIGINAL_FILENAME"
    FILE_METADATA = "FILE_METADATA"
    RECOVERY_SECRET = "RECOVERY_SECRET"
    CRYPTOGRAPHIC_KEY = "CRYPTOGRAPHIC_KEY"
    REQUEST_HEADER = "REQUEST_HEADER"
    RAW_ERROR = "RAW_ERROR"


SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1 = (
    SubmissionAuditAllowedPayloadField.SYSTEM_GENERATED_IDENTIFIER,
    SubmissionAuditAllowedPayloadField.EVENT_OPERATION_CODE,
    SubmissionAuditAllowedPayloadField.ATTEMPT_STATE,
    SubmissionAuditAllowedPayloadField.ATTEMPT_VERSION,
    SubmissionAuditAllowedPayloadField.CALLER_IDENTITY,
    SubmissionAuditAllowedPayloadField.IDEMPOTENCY_CONTEXT,
    SubmissionAuditAllowedPayloadField.ANTI_REPLAY_CONTEXT,
)

SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1 = (
    SubmissionAuditForbiddenPayloadField.REPORT_TEXT,
    SubmissionAuditForbiddenPayloadField.ATTACHMENT_CONTENT,
    SubmissionAuditForbiddenPayloadField.ORIGINAL_FILENAME,
    SubmissionAuditForbiddenPayloadField.FILE_METADATA,
    SubmissionAuditForbiddenPayloadField.RECOVERY_SECRET,
    SubmissionAuditForbiddenPayloadField.CRYPTOGRAPHIC_KEY,
    SubmissionAuditForbiddenPayloadField.REQUEST_HEADER,
    SubmissionAuditForbiddenPayloadField.RAW_ERROR,
)


@dataclass(frozen=True, slots=True)
class SubmissionAuditPhaseDescriptorV1:
    phase: SubmissionAuditPhase
    audit_event_type: AuditEventType
    required_timing: SubmissionAuditTiming
    authorization_window_ms: int
    durable_receipt_required: bool


@dataclass(frozen=True, slots=True)
class SubmissionAuditPayloadPolicyV1:
    allowed_fields: tuple[SubmissionAuditAllowedPayloadField, ...]
    forbidden_fields: tuple[SubmissionAuditForbiddenPayloadField, ...]


@dataclass(frozen=True, slots=True)
class SubmissionAuditProfileV1:
    scheme_version: int
    phases: tuple[SubmissionAuditPhaseDescriptorV1, ...]
    payload_policy: SubmissionAuditPayloadPolicyV1


@dataclass(frozen=True, slots=True)
class StructurallyValidSubmissionAuditProfileV1:
    profile: SubmissionAuditProfileV1

    @property
    def appends_audit_event(self) -> bool:
        return False

    @property
    def creates_audit_receipt(self) -> bool:
        return False

    @property
    def verifies_audit_receipt(self) -> bool:
        return False

    @property
    def inspects_attempt_state(self) -> bool:
        return False

    @property
    def calls_audit_service(self) -> bool:
        return False

    @property
    def creates_report_key(self) -> bool:
        return False

    @property
    def persists_submission_metadata(self) -> bool:
        return False

    @property
    def authorizes_submission(self) -> bool:
        return False


SUBMISSION_AUDIT_PHASES_V1 = (
    SubmissionAuditPhaseDescriptorV1(
        phase=SubmissionAuditPhase.ACCEPTANCE_REQUESTED,
        audit_event_type=AuditEventType.SUBMISSION_ACCEPTANCE_REQUESTED,
        required_timing=(
            SubmissionAuditTiming.BEFORE_KEY_OR_MATERIAL_CREATION
        ),
        authorization_window_ms=(
            SUBMISSION_AUDIT_REQUESTED_AUTHORIZATION_WINDOW_MS
        ),
        durable_receipt_required=True,
    ),
    SubmissionAuditPhaseDescriptorV1(
        phase=SubmissionAuditPhase.RECEIVED,
        audit_event_type=AuditEventType.SUBMISSION_RECEIVED,
        required_timing=(
            SubmissionAuditTiming.AFTER_STAGED_CIPHERTEXT_DURABILITY
        ),
        authorization_window_ms=SUBMISSION_AUDIT_RECEIVED_AUTHORIZATION_WINDOW_MS,
        durable_receipt_required=True,
    ),
    SubmissionAuditPhaseDescriptorV1(
        phase=SubmissionAuditPhase.ACCEPTANCE_FAILED,
        audit_event_type=AuditEventType.SUBMISSION_ACCEPTANCE_FAILED,
        required_timing=SubmissionAuditTiming.BEST_EFFORT_ABORT_EVIDENCE,
        authorization_window_ms=SUBMISSION_AUDIT_FAILED_AUTHORIZATION_WINDOW_MS,
        durable_receipt_required=False,
    ),
)


def _reject() -> Never:
    raise SubmissionAuditDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_phase(value: object) -> SubmissionAuditPhase:
    if isinstance(value, SubmissionAuditPhase):
        return value
    _reject()


def _require_timing(value: object) -> SubmissionAuditTiming:
    if isinstance(value, SubmissionAuditTiming):
        return value
    _reject()


def _require_audit_event_type(value: object) -> AuditEventType:
    if isinstance(value, AuditEventType):
        return value
    _reject()


def _normalize_phase_descriptor(
    descriptor: SubmissionAuditPhaseDescriptorV1,
) -> SubmissionAuditPhaseDescriptorV1:
    if type(descriptor) is not SubmissionAuditPhaseDescriptorV1:
        _reject()
    phase = _require_phase(descriptor.phase)
    audit_event_type = _require_audit_event_type(descriptor.audit_event_type)
    required_timing = _require_timing(descriptor.required_timing)
    expected_by_phase = {
        item.phase: item for item in SUBMISSION_AUDIT_PHASES_V1
    }
    expected = expected_by_phase.get(phase)
    if expected is None:
        _reject()
    return SubmissionAuditPhaseDescriptorV1(
        phase=phase,
        audit_event_type=audit_event_type,
        required_timing=required_timing,
        authorization_window_ms=_require_uint_exact(
            descriptor.authorization_window_ms,
            expected=expected.authorization_window_ms,
        ),
        durable_receipt_required=_require_bool_exact(
            descriptor.durable_receipt_required,
            expected=expected.durable_receipt_required,
        ),
    )


def _require_phase_sequence(
    value: object,
) -> tuple[SubmissionAuditPhaseDescriptorV1, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_normalize_phase_descriptor(item) for item in value)
    if normalized != SUBMISSION_AUDIT_PHASES_V1:
        _reject()
    return normalized


def _require_allowed_payload_field(
    value: object,
) -> SubmissionAuditAllowedPayloadField:
    if isinstance(value, SubmissionAuditAllowedPayloadField):
        return value
    _reject()


def _require_forbidden_payload_field(
    value: object,
) -> SubmissionAuditForbiddenPayloadField:
    if isinstance(value, SubmissionAuditForbiddenPayloadField):
        return value
    _reject()


def _require_allowed_payload_fields(
    value: object,
) -> tuple[SubmissionAuditAllowedPayloadField, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_allowed_payload_field(item) for item in value)
    if normalized != SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1:
        _reject()
    return normalized


def _require_forbidden_payload_fields(
    value: object,
) -> tuple[SubmissionAuditForbiddenPayloadField, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_payload_field(item) for item in value)
    if normalized != SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1:
        _reject()
    return normalized


def validate_submission_audit_payload_policy_v1(
    policy: SubmissionAuditPayloadPolicyV1,
) -> SubmissionAuditPayloadPolicyV1:
    if type(policy) is not SubmissionAuditPayloadPolicyV1:
        _reject()
    return SubmissionAuditPayloadPolicyV1(
        allowed_fields=_require_allowed_payload_fields(policy.allowed_fields),
        forbidden_fields=_require_forbidden_payload_fields(
            policy.forbidden_fields
        ),
    )


def validate_submission_audit_phase_descriptor_v1(
    descriptor: SubmissionAuditPhaseDescriptorV1,
) -> SubmissionAuditPhaseDescriptorV1:
    normalized = _normalize_phase_descriptor(descriptor)
    expected_by_phase = {
        item.phase: item for item in SUBMISSION_AUDIT_PHASES_V1
    }
    expected = expected_by_phase.get(normalized.phase)
    if normalized != expected:
        _reject()
    return normalized


def validate_submission_audit_profile_v1(
    profile: SubmissionAuditProfileV1,
) -> StructurallyValidSubmissionAuditProfileV1:
    if type(profile) is not SubmissionAuditProfileV1:
        _reject()
    normalized = SubmissionAuditProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SUBMISSION_AUDIT_PROFILE_VERSION,
        ),
        phases=_require_phase_sequence(profile.phases),
        payload_policy=validate_submission_audit_payload_policy_v1(
            profile.payload_policy
        ),
    )
    return StructurallyValidSubmissionAuditProfileV1(profile=normalized)


def expected_submission_audit_profile_v1() -> SubmissionAuditProfileV1:
    """Return only the approved submission-audit metadata profile."""

    return SubmissionAuditProfileV1(
        scheme_version=SUBMISSION_AUDIT_PROFILE_VERSION,
        phases=SUBMISSION_AUDIT_PHASES_V1,
        payload_policy=SubmissionAuditPayloadPolicyV1(
            allowed_fields=SUBMISSION_AUDIT_ALLOWED_PAYLOAD_FIELDS_V1,
            forbidden_fields=SUBMISSION_AUDIT_FORBIDDEN_PAYLOAD_FIELDS_V1,
        ),
    )
