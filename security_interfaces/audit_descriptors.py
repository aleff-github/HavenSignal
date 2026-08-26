"""Inert, structural audit descriptors from the owner-approved v1 profile.

This module does not encode CBOR, parse COSE, verify signatures, append events,
or authorize protected actions. It models only registry values and structural
rules that are exact in docs/23.
"""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Never

from .errors import AuditDescriptorRejected


AUDIT_PROTOCOL_VERSION = 1
MAX_CBOR_UINT = (1 << 64) - 1


class AuditActorKind(StrEnum):
    NONE = "NONE"
    OPERATOR = "OPERATOR"
    APPLICATION_ADMIN = "APPLICATION_ADMIN"
    SERVICE = "SERVICE"


class AuditEventType(StrEnum):
    SUBMISSION_ACCEPTANCE_REQUESTED = "SUBMISSION_ACCEPTANCE_REQUESTED"
    SUBMISSION_RECEIVED = "SUBMISSION_RECEIVED"
    SUBMISSION_ACCEPTANCE_FAILED = "SUBMISSION_ACCEPTANCE_FAILED"
    CLAIM = "CLAIM"
    CLAIM_EXPIRED = "CLAIM_EXPIRED"
    OPEN_REQUESTED = "OPEN_REQUESTED"
    OPEN_AUTHORIZED = "OPEN_AUTHORIZED"
    OPEN_COMPLETED = "OPEN_COMPLETED"
    OPEN_FAILED = "OPEN_FAILED"
    ATTACHMENT_VIEW_REQUESTED = "ATTACHMENT_VIEW_REQUESTED"
    ATTACHMENT_VIEWED = "ATTACHMENT_VIEWED"
    ATTACHMENT_VIEW_FAILED = "ATTACHMENT_VIEW_FAILED"
    INTERRUPTED = "INTERRUPTED"
    REOPEN_REQUESTED = "REOPEN_REQUESTED"
    REOPEN_AUTHORIZED = "REOPEN_AUTHORIZED"
    REOPEN_COMPLETED = "REOPEN_COMPLETED"
    REOPEN_FAILED = "REOPEN_FAILED"
    RESPONSE_RETRIEVAL_REQUESTED = "RESPONSE_RETRIEVAL_REQUESTED"
    RESPONSE_RETRIEVAL_COMPLETED = "RESPONSE_RETRIEVAL_COMPLETED"
    RESPONSE_RETRIEVAL_FAILED = "RESPONSE_RETRIEVAL_FAILED"
    EMERGENCY_EXPORT_REQUESTED = "EMERGENCY_EXPORT_REQUESTED"
    EMERGENCY_EXPORT_AUTHORIZED = "EMERGENCY_EXPORT_AUTHORIZED"
    EMERGENCY_EXPORT_COMPLETED = "EMERGENCY_EXPORT_COMPLETED"
    EMERGENCY_EXPORT_FAILED = "EMERGENCY_EXPORT_FAILED"
    FINALIZATION_REQUESTED = "FINALIZATION_REQUESTED"
    FINALIZATION_AUTHORIZED = "FINALIZATION_AUTHORIZED"
    FINALIZATION_COMPLETED = "FINALIZATION_COMPLETED"
    FINALIZATION_FAILED = "FINALIZATION_FAILED"
    RESPONSE_AVAILABLE = "RESPONSE_AVAILABLE"
    REPORT_KEY_DESTROYED = "REPORT_KEY_DESTROYED"
    CONTENT_DELETE_STARTED = "CONTENT_DELETE_STARTED"
    CONTENT_DELETE_COMPLETED = "CONTENT_DELETE_COMPLETED"
    CONTENT_DELETE_FAILED = "CONTENT_DELETE_FAILED"
    DELETE_REPORT_REQUESTED = "DELETE_REPORT_REQUESTED"
    DELETE_REPORT_AUTHORIZED = "DELETE_REPORT_AUTHORIZED"
    DELETE_REPORT_COMPLETED = "DELETE_REPORT_COMPLETED"
    DELETE_REPORT_FAILED = "DELETE_REPORT_FAILED"
    SECURITY_CONFIGURATION_CHANGED = "SECURITY_CONFIGURATION_CHANGED"
    OPERATOR_AUTHENTICATION_EVENT = "OPERATOR_AUTHENTICATION_EVENT"
    ADMIN_AUDIT_ACCESS = "ADMIN_AUDIT_ACCESS"


AUTHORIZATION_WINDOWS_MS = MappingProxyType(
    {
        AuditEventType.SUBMISSION_ACCEPTANCE_REQUESTED: 15 * 60 * 1000,
        AuditEventType.SUBMISSION_RECEIVED: 60 * 1000,
        AuditEventType.OPEN_REQUESTED: 30 * 1000,
        AuditEventType.REOPEN_REQUESTED: 30 * 1000,
        AuditEventType.ATTACHMENT_VIEW_REQUESTED: 30 * 1000,
        AuditEventType.RESPONSE_RETRIEVAL_REQUESTED: 30 * 1000,
        AuditEventType.FINALIZATION_REQUESTED: 60 * 1000,
        AuditEventType.EMERGENCY_EXPORT_REQUESTED: 60 * 1000,
        AuditEventType.DELETE_REPORT_REQUESTED: 60 * 1000,
    }
)

# docs/23 gives REPORT_KEY_DESTROYED a five-minute window only when it is used
# before response publication. The exact operation registry needed to
# distinguish that use from deletion outcomes is not yet complete, so Stage A
# rejects this context instead of guessing.
CONTEXT_DEPENDENT_AUTHORIZATION_EVENTS = frozenset(
    {AuditEventType.REPORT_KEY_DESTROYED}
)


@dataclass(frozen=True, slots=True)
class AuditActorReferenceV1:
    actor_kind: AuditActorKind | str
    actor_id: bytes | None


@dataclass(frozen=True, slots=True)
class AuditReplayContextV1:
    idempotency_id: bytes
    action_nonce: bytes


@dataclass(frozen=True, slots=True)
class AuditAcceptanceClaimsV1:
    version: int
    log_id: bytes
    event_id: bytes
    leaf_index: int
    leaf_hash: bytes
    accepted_at_ms: int
    authorization_not_after_ms: int | None


@dataclass(frozen=True, slots=True)
class StructurallyValidAuditAcceptanceClaimsV1:
    """Shape evidence only; never signature or authorization evidence."""

    event_type: AuditEventType
    claims: AuditAcceptanceClaimsV1
    authorization_window_ms: int | None

    @property
    def authorizes_protected_action(self) -> bool:
        return False


def _reject() -> Never:
    raise AuditDescriptorRejected()


def _require_exact_bytes(value: object, *, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _reject()
    return value


def _require_uint(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_CBOR_UINT:
        _reject()
    return value


def _require_actor_kind(value: object) -> AuditActorKind:
    if isinstance(value, AuditActorKind):
        return value
    if type(value) is str:
        for actor_kind in AuditActorKind:
            if value == actor_kind.value:
                return actor_kind
    _reject()


def _require_event_type(value: object) -> AuditEventType:
    if isinstance(value, AuditEventType):
        return value
    if type(value) is str:
        for event_type in AuditEventType:
            if value == event_type.value:
                return event_type
    _reject()


def validate_audit_actor_reference_v1(
    reference: AuditActorReferenceV1,
) -> AuditActorReferenceV1:
    if type(reference) is not AuditActorReferenceV1:
        _reject()

    actor_kind = _require_actor_kind(reference.actor_kind)
    if actor_kind == AuditActorKind.NONE:
        if reference.actor_id is not None:
            _reject()
        actor_id = None
    else:
        actor_id = _require_exact_bytes(reference.actor_id, size=16)

    return AuditActorReferenceV1(actor_kind=actor_kind, actor_id=actor_id)


def validate_audit_replay_context_v1(
    context: AuditReplayContextV1,
) -> AuditReplayContextV1:
    if type(context) is not AuditReplayContextV1:
        _reject()
    return AuditReplayContextV1(
        idempotency_id=_require_exact_bytes(context.idempotency_id, size=16),
        action_nonce=_require_exact_bytes(context.action_nonce, size=32),
    )


def validate_audit_acceptance_claims_v1(
    *,
    event_type: AuditEventType | str,
    claims: AuditAcceptanceClaimsV1,
) -> StructurallyValidAuditAcceptanceClaimsV1:
    """Validate exact claim shape/lifetime without verifying a COSE receipt."""

    normalized_event_type = _require_event_type(event_type)
    if type(claims) is not AuditAcceptanceClaimsV1:
        _reject()
    if type(claims.version) is not int or claims.version != AUDIT_PROTOCOL_VERSION:
        _reject()

    accepted_at_ms = _require_uint(claims.accepted_at_ms)
    if normalized_event_type in CONTEXT_DEPENDENT_AUTHORIZATION_EVENTS:
        _reject()
    expected_window_ms = AUTHORIZATION_WINDOWS_MS.get(normalized_event_type)
    if expected_window_ms is None:
        if claims.authorization_not_after_ms is not None:
            _reject()
        authorization_not_after_ms = None
    else:
        if accepted_at_ms > MAX_CBOR_UINT - expected_window_ms:
            _reject()
        authorization_not_after_ms = _require_uint(
            claims.authorization_not_after_ms
        )
        if authorization_not_after_ms != accepted_at_ms + expected_window_ms:
            _reject()

    normalized_claims = AuditAcceptanceClaimsV1(
        version=AUDIT_PROTOCOL_VERSION,
        log_id=_require_exact_bytes(claims.log_id, size=32),
        event_id=_require_exact_bytes(claims.event_id, size=16),
        leaf_index=_require_uint(claims.leaf_index),
        leaf_hash=_require_exact_bytes(claims.leaf_hash, size=32),
        accepted_at_ms=accepted_at_ms,
        authorization_not_after_ms=authorization_not_after_ms,
    )
    return StructurallyValidAuditAcceptanceClaimsV1(
        event_type=normalized_event_type,
        claims=normalized_claims,
        authorization_window_ms=expected_window_ms,
    )
