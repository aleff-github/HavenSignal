"""Inert report-bound step-up components from the approved v1 profile.

This module contains no challenge, browser handle, credential, WebAuthn
verification, HMAC operation, authorization persistence, or consumption path.
The closed operation/state/artifact profiles are deliberately not guessed.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Never

from .audit_descriptors import MAX_CBOR_UINT
from .errors import StepUpDescriptorRejected


STEP_UP_PROTOCOL_VERSION = 1
STEP_UP_TTL_MS = 120 * 1000


class WebAuthnCoseAlgorithm(IntEnum):
    ES256 = -7
    EDDSA = -8


class StepUpArtifactBindingPurpose(StrEnum):
    STEP_UP_ARTIFACT_BINDING = "STEP_UP_ARTIFACT_BINDING"


@dataclass(frozen=True, slots=True)
class ReportStepUpContextV1:
    authorization_id: bytes
    operator_id: bytes
    session_id: bytes
    report_id: bytes
    response_id: bytes | None
    finalization_id: bytes | None
    lease_id: bytes
    lease_generation: int
    report_state_version: int


@dataclass(frozen=True, slots=True)
class StepUpArtifactBindingProfileV1:
    purpose: StepUpArtifactBindingPurpose | str
    binding_key_epoch: int


@dataclass(frozen=True, slots=True)
class StepUpTimingV1:
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class StepUpUnusedStateV1:
    consumed_at: None = None
    consumed_by_operation_id: None = None


@dataclass(frozen=True, slots=True)
class StructurallyValidReportStepUpComponentsV1:
    context: ReportStepUpContextV1
    artifact_profile: StepUpArtifactBindingProfileV1
    timing: StepUpTimingV1
    unused_state: StepUpUnusedStateV1

    @property
    def has_complete_operation_profile(self) -> bool:
        return False

    @property
    def verifies_webauthn(self) -> bool:
        return False

    @property
    def verifies_artifact_binding(self) -> bool:
        return False

    @property
    def authorizes_protected_action(self) -> bool:
        return False


def _reject() -> Never:
    raise StepUpDescriptorRejected()


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


def _require_binding_purpose(value: object) -> StepUpArtifactBindingPurpose:
    if isinstance(value, StepUpArtifactBindingPurpose):
        return value
    if type(value) is str:
        for purpose in StepUpArtifactBindingPurpose:
            if value == purpose.value:
                return purpose
    _reject()


def validate_webauthn_cose_algorithm(
    algorithm: WebAuthnCoseAlgorithm | int,
) -> WebAuthnCoseAlgorithm:
    if isinstance(algorithm, WebAuthnCoseAlgorithm):
        return algorithm
    if type(algorithm) is int:
        for allowed in WebAuthnCoseAlgorithm:
            if algorithm == allowed.value:
                return allowed
    _reject()


def validate_report_step_up_context_v1(
    context: ReportStepUpContextV1,
) -> ReportStepUpContextV1:
    if type(context) is not ReportStepUpContextV1:
        _reject()
    return ReportStepUpContextV1(
        authorization_id=_require_exact_bytes(context.authorization_id, size=16),
        operator_id=_require_exact_bytes(context.operator_id, size=16),
        session_id=_require_exact_bytes(context.session_id, size=16),
        report_id=_require_exact_bytes(context.report_id, size=16),
        response_id=_require_optional_exact_bytes(context.response_id, size=16),
        finalization_id=_require_optional_exact_bytes(
            context.finalization_id,
            size=16,
        ),
        lease_id=_require_exact_bytes(context.lease_id, size=16),
        lease_generation=_require_uint(context.lease_generation),
        report_state_version=_require_uint(context.report_state_version),
    )


def validate_step_up_artifact_binding_profile_v1(
    profile: StepUpArtifactBindingProfileV1,
) -> StepUpArtifactBindingProfileV1:
    if type(profile) is not StepUpArtifactBindingProfileV1:
        _reject()
    return StepUpArtifactBindingProfileV1(
        purpose=_require_binding_purpose(profile.purpose),
        binding_key_epoch=_require_uint(profile.binding_key_epoch),
    )


def validate_step_up_timing_v1(timing: StepUpTimingV1) -> StepUpTimingV1:
    if type(timing) is not StepUpTimingV1:
        _reject()
    if (
        type(timing.issued_at) is not datetime
        or type(timing.expires_at) is not datetime
        or timing.issued_at.tzinfo is None
        or timing.expires_at.tzinfo is None
        or timing.issued_at.utcoffset() is None
        or timing.expires_at.utcoffset() is None
    ):
        _reject()
    try:
        expected_expiry = timing.issued_at + timedelta(milliseconds=STEP_UP_TTL_MS)
    except OverflowError:
        _reject()
    if timing.expires_at != expected_expiry:
        _reject()
    return StepUpTimingV1(
        issued_at=timing.issued_at,
        expires_at=timing.expires_at,
    )


def validate_step_up_unused_state_v1(
    state: StepUpUnusedStateV1,
) -> StepUpUnusedStateV1:
    if (
        type(state) is not StepUpUnusedStateV1
        or state.consumed_at is not None
        or state.consumed_by_operation_id is not None
    ):
        _reject()
    return StepUpUnusedStateV1()


def validate_report_step_up_components_v1(
    *,
    context: ReportStepUpContextV1,
    artifact_profile: StepUpArtifactBindingProfileV1,
    timing: StepUpTimingV1,
    unused_state: StepUpUnusedStateV1,
) -> StructurallyValidReportStepUpComponentsV1:
    """Validate only approved structure; never issue or authorize step-up."""

    return StructurallyValidReportStepUpComponentsV1(
        context=validate_report_step_up_context_v1(context),
        artifact_profile=validate_step_up_artifact_binding_profile_v1(
            artifact_profile
        ),
        timing=validate_step_up_timing_v1(timing),
        unused_state=validate_step_up_unused_state_v1(unused_state),
    )
