"""Inert foundations for the approved administrative step-up v2 profile.

This module validates only exact identity, timing, binding-purpose, and unused
state shapes. Closed operation/target/artifact profiles, challenges, handles,
credentials, binding bytes, persistence, consumption, and authorization remain
absent.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Never

from .audit_descriptors import MAX_CBOR_UINT
from .errors import StepUpDescriptorRejected
from .step_up_descriptors import StepUpArtifactBindingPurpose


ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION = 2
ADMINISTRATIVE_STEP_UP_TTL_MS = 120 * 1000


@dataclass(frozen=True, slots=True)
class AdministrativeStepUpIdentityV2:
    authorization_id: bytes
    administrator_id: bytes
    session_id: bytes
    device_id: bytes


@dataclass(frozen=True, slots=True)
class AdministrativeStepUpArtifactProfileV2:
    purpose: StepUpArtifactBindingPurpose | str
    binding_key_epoch: int


@dataclass(frozen=True, slots=True)
class AdministrativeStepUpTimingV2:
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AdministrativeStepUpUnusedStateV2:
    consumed_at: None = None
    consumed_by_operation_id: None = None


@dataclass(frozen=True, slots=True)
class StructurallyValidAdministrativeStepUpFoundationsV2:
    identity: AdministrativeStepUpIdentityV2
    artifact_profile: AdministrativeStepUpArtifactProfileV2
    timing: AdministrativeStepUpTimingV2
    unused_state: AdministrativeStepUpUnusedStateV2

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
    def authorizes_administrative_action(self) -> bool:
        return False

    @property
    def authorizes_flood_deletion(self) -> bool:
        return False


def _reject() -> Never:
    raise StepUpDescriptorRejected()


def _require_exact_bytes(value: object, *, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _reject()
    return value


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


def validate_administrative_step_up_identity_v2(
    identity: AdministrativeStepUpIdentityV2,
) -> AdministrativeStepUpIdentityV2:
    if type(identity) is not AdministrativeStepUpIdentityV2:
        _reject()
    return AdministrativeStepUpIdentityV2(
        authorization_id=_require_exact_bytes(
            identity.authorization_id,
            size=16,
        ),
        administrator_id=_require_exact_bytes(
            identity.administrator_id,
            size=16,
        ),
        session_id=_require_exact_bytes(identity.session_id, size=16),
        device_id=_require_exact_bytes(identity.device_id, size=16),
    )


def validate_administrative_step_up_artifact_profile_v2(
    profile: AdministrativeStepUpArtifactProfileV2,
) -> AdministrativeStepUpArtifactProfileV2:
    if type(profile) is not AdministrativeStepUpArtifactProfileV2:
        _reject()
    return AdministrativeStepUpArtifactProfileV2(
        purpose=_require_binding_purpose(profile.purpose),
        binding_key_epoch=_require_uint(profile.binding_key_epoch),
    )


def validate_administrative_step_up_timing_v2(
    timing: AdministrativeStepUpTimingV2,
) -> AdministrativeStepUpTimingV2:
    if type(timing) is not AdministrativeStepUpTimingV2:
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
        expected_expiry = timing.issued_at + timedelta(
            milliseconds=ADMINISTRATIVE_STEP_UP_TTL_MS
        )
    except OverflowError:
        _reject()
    if timing.expires_at != expected_expiry:
        _reject()
    return AdministrativeStepUpTimingV2(
        issued_at=timing.issued_at,
        expires_at=timing.expires_at,
    )


def validate_administrative_step_up_unused_state_v2(
    state: AdministrativeStepUpUnusedStateV2,
) -> AdministrativeStepUpUnusedStateV2:
    if (
        type(state) is not AdministrativeStepUpUnusedStateV2
        or state.consumed_at is not None
        or state.consumed_by_operation_id is not None
    ):
        _reject()
    return AdministrativeStepUpUnusedStateV2()


def validate_administrative_step_up_foundations_v2(
    *,
    identity: AdministrativeStepUpIdentityV2,
    artifact_profile: AdministrativeStepUpArtifactProfileV2,
    timing: AdministrativeStepUpTimingV2,
    unused_state: AdministrativeStepUpUnusedStateV2,
) -> StructurallyValidAdministrativeStepUpFoundationsV2:
    """Validate inert foundations without issuing or authorizing step-up."""

    return StructurallyValidAdministrativeStepUpFoundationsV2(
        identity=validate_administrative_step_up_identity_v2(identity),
        artifact_profile=(
            validate_administrative_step_up_artifact_profile_v2(
                artifact_profile
            )
        ),
        timing=validate_administrative_step_up_timing_v2(timing),
        unused_state=validate_administrative_step_up_unused_state_v2(
            unused_state
        ),
    )
