"""Inert structural descriptors from the owner-approved alert v1 profile.

No type in this module sends, persists, queues, acknowledges, or proves durable
acceptance of an alert. Only registries and field rules exact in docs/31 are
represented here.
"""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Never

from .audit_descriptors import MAX_CBOR_UINT, AuditActorKind
from .errors import AlertDescriptorRejected


class AlertSeverity(StrEnum):
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(StrEnum):
    AUDIT_GAP_DETECTED = "AUDIT_GAP_DETECTED"
    AUDIT_FORK_OR_ROLLBACK = "AUDIT_FORK_OR_ROLLBACK"
    AUDIT_CESSATION = "AUDIT_CESSATION"
    AUDIT_INCLUSION_LATE = "AUDIT_INCLUSION_LATE"
    CIPHERTEXT_DELETE_PERSISTENT_FAILURE = (
        "CIPHERTEXT_DELETE_PERSISTENT_FAILURE"
    )
    EMERGENCY_EXPORT_REQUESTED = "EMERGENCY_EXPORT_REQUESTED"
    EXPORT_STAGING_CLEANUP_FAILURE = "EXPORT_STAGING_CLEANUP_FAILURE"
    KEY_STATE_MISMATCH = "KEY_STATE_MISMATCH"
    WEBAUTHN_COUNTER_REGRESSION = "WEBAUTHN_COUNTER_REGRESSION"
    SECURITY_CREDENTIAL_CHANGE = "SECURITY_CREDENTIAL_CHANGE"


class AlertDeliveryState(StrEnum):
    QUEUED = "QUEUED"
    DELIVERED = "DELIVERED"
    DELIVERY_RETRY = "DELIVERY_RETRY"


ALERT_SEVERITY_BY_TYPE = MappingProxyType(
    {
        AlertType.AUDIT_GAP_DETECTED: AlertSeverity.CRITICAL,
        AlertType.AUDIT_FORK_OR_ROLLBACK: AlertSeverity.CRITICAL,
        AlertType.AUDIT_CESSATION: AlertSeverity.CRITICAL,
        AlertType.AUDIT_INCLUSION_LATE: AlertSeverity.CRITICAL,
        AlertType.CIPHERTEXT_DELETE_PERSISTENT_FAILURE: AlertSeverity.HIGH,
        AlertType.EMERGENCY_EXPORT_REQUESTED: AlertSeverity.CRITICAL,
        AlertType.EXPORT_STAGING_CLEANUP_FAILURE: AlertSeverity.CRITICAL,
        AlertType.KEY_STATE_MISMATCH: AlertSeverity.CRITICAL,
        AlertType.WEBAUTHN_COUNTER_REGRESSION: AlertSeverity.CRITICAL,
        AlertType.SECURITY_CREDENTIAL_CHANGE: AlertSeverity.HIGH,
    }
)


@dataclass(frozen=True, slots=True)
class AlertProfileReferenceV1:
    alert_type: AlertType | str
    severity: AlertSeverity | str


@dataclass(frozen=True, slots=True)
class AlertActorReferenceV1:
    actor_kind: AuditActorKind | str
    actor_id: bytes | None


@dataclass(frozen=True, slots=True)
class AlertOperationReferenceV1:
    operation_id: bytes
    idempotency_id: bytes
    source_event_id: bytes | None


@dataclass(frozen=True, slots=True)
class AlertAcceptanceConfirmationV1:
    """Alert-Service response fields; not evidence of a durable commit."""

    alert_id: bytes
    accepted_at_ms: int


@dataclass(frozen=True, slots=True)
class StructurallyValidAlertAcceptanceConfirmationV1:
    confirmation: AlertAcceptanceConfirmationV1

    @property
    def proves_durable_acceptance(self) -> bool:
        return False

    @property
    def authorizes_protected_action(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class AlertAcknowledgementReferenceV1:
    acknowledged_at_ms: int | None
    acknowledged_by: bytes | None


def _reject() -> Never:
    raise AlertDescriptorRejected()


def _require_exact_bytes(value: object, *, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _reject()
    return value


def _require_optional_exact_bytes(value: object, *, size: int) -> bytes | None:
    if value is None:
        return None
    return _require_exact_bytes(value, size=size)


def _require_uint(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_CBOR_UINT:
        _reject()
    return value


def _require_alert_type(value: object) -> AlertType:
    if isinstance(value, AlertType):
        return value
    if type(value) is str:
        for alert_type in AlertType:
            if value == alert_type.value:
                return alert_type
    _reject()


def _require_alert_severity(value: object) -> AlertSeverity:
    if isinstance(value, AlertSeverity):
        return value
    if type(value) is str:
        for severity in AlertSeverity:
            if value == severity.value:
                return severity
    _reject()


def _require_delivery_state(value: object) -> AlertDeliveryState:
    if isinstance(value, AlertDeliveryState):
        return value
    if type(value) is str:
        for delivery_state in AlertDeliveryState:
            if value == delivery_state.value:
                return delivery_state
    _reject()


def _require_actor_kind(value: object) -> AuditActorKind:
    if isinstance(value, AuditActorKind):
        return value
    if type(value) is str:
        for actor_kind in AuditActorKind:
            if value == actor_kind.value:
                return actor_kind
    _reject()


def validate_alert_profile_reference_v1(
    reference: AlertProfileReferenceV1,
) -> AlertProfileReferenceV1:
    if type(reference) is not AlertProfileReferenceV1:
        _reject()
    alert_type = _require_alert_type(reference.alert_type)
    severity = _require_alert_severity(reference.severity)
    if ALERT_SEVERITY_BY_TYPE[alert_type] != severity:
        _reject()
    return AlertProfileReferenceV1(alert_type=alert_type, severity=severity)


def validate_alert_delivery_state_v1(
    delivery_state: AlertDeliveryState | str,
) -> AlertDeliveryState:
    return _require_delivery_state(delivery_state)


def validate_alert_actor_reference_v1(
    reference: AlertActorReferenceV1,
) -> AlertActorReferenceV1:
    if type(reference) is not AlertActorReferenceV1:
        _reject()
    actor_kind = _require_actor_kind(reference.actor_kind)
    if actor_kind == AuditActorKind.NONE:
        if reference.actor_id is not None:
            _reject()
        actor_id = None
    else:
        actor_id = _require_exact_bytes(reference.actor_id, size=16)
    return AlertActorReferenceV1(actor_kind=actor_kind, actor_id=actor_id)


def validate_alert_operation_reference_v1(
    reference: AlertOperationReferenceV1,
) -> AlertOperationReferenceV1:
    if type(reference) is not AlertOperationReferenceV1:
        _reject()
    return AlertOperationReferenceV1(
        operation_id=_require_exact_bytes(reference.operation_id, size=16),
        idempotency_id=_require_exact_bytes(reference.idempotency_id, size=16),
        source_event_id=_require_optional_exact_bytes(
            reference.source_event_id,
            size=16,
        ),
    )


def validate_alert_acceptance_confirmation_v1(
    confirmation: AlertAcceptanceConfirmationV1,
) -> StructurallyValidAlertAcceptanceConfirmationV1:
    """Validate response shape only; no durability or service identity proof."""

    if type(confirmation) is not AlertAcceptanceConfirmationV1:
        _reject()
    normalized = AlertAcceptanceConfirmationV1(
        alert_id=_require_exact_bytes(confirmation.alert_id, size=16),
        accepted_at_ms=_require_uint(confirmation.accepted_at_ms),
    )
    return StructurallyValidAlertAcceptanceConfirmationV1(
        confirmation=normalized
    )


def validate_alert_acknowledgement_reference_v1(
    reference: AlertAcknowledgementReferenceV1,
) -> AlertAcknowledgementReferenceV1:
    """Validate only the accepted-record pair; this does not acknowledge."""

    if type(reference) is not AlertAcknowledgementReferenceV1:
        _reject()
    if reference.acknowledged_at_ms is None:
        if reference.acknowledged_by is not None:
            _reject()
        return AlertAcknowledgementReferenceV1(None, None)
    if reference.acknowledged_by is None:
        _reject()
    return AlertAcknowledgementReferenceV1(
        acknowledged_at_ms=_require_uint(reference.acknowledged_at_ms),
        acknowledged_by=_require_exact_bytes(
            reference.acknowledged_by,
            size=16,
        ),
    )
