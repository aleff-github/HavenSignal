"""Inert Response Note crypto descriptors from the approved v1 profile.

This module validates only static profile shapes. It does not canonicalize
Response Notes, create frames, encrypt, decrypt, parse envelopes, produce AAD,
hold key handles, call a Key Service, or authorize response use.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import ResponseCryptoDescriptorRejected


RESPONSE_CRYPTO_PROTOCOL_VERSION = 1
RESPONSE_AEAD_ALGORITHM_ID = 1
RESPONSE_CONTENT_PROFILE_ID = 1
RESPONSE_AAD_PURPOSE = "RESPONSE_NOTE"

RESPONSE_DEK_BYTES = 32
RESPONSE_NONCE_BYTES = 24
RESPONSE_AEAD_TAG_BYTES = 16
RESPONSE_PLAINTEXT_FRAME_BYTES = 20_005
RESPONSE_CIPHERTEXT_AND_TAG_BYTES = 20_021
RESPONSE_MAX_SCALAR_VALUES = 5_000
RESPONSE_MAX_UTF8_BYTES = 20_000

RESPONSE_REPORT_ID_BYTES = 16
RESPONSE_ID_BYTES = 16
RESPONSE_FINALIZATION_ID_BYTES = 16
RESPONSE_KEY_HANDLE_BYTES = 32


class ResponseAeadAlgorithm(StrEnum):
    XCHACHA20_POLY1305_IETF = "XCHACHA20_POLY1305_IETF"


class ResponseContentProfile(StrEnum):
    CANONICAL_UTF8_FIXED_FRAME = "CANONICAL_UTF8_FIXED_FRAME"


class ResponseKeyOperation(StrEnum):
    CREATE_AND_ENCRYPT_RESPONSE = "CREATE_AND_ENCRYPT_RESPONSE"
    VERIFY_RESPONSE_ENVELOPE = "VERIFY_RESPONSE_ENVELOPE"
    ACTIVATE_RESPONSE_KEY = "ACTIVATE_RESPONSE_KEY"
    ARM_RESPONSE_EXPIRY = "ARM_RESPONSE_EXPIRY"
    DECRYPT_RESPONSE = "DECRYPT_RESPONSE"
    DESTROY_RESPONSE_KEY = "DESTROY_RESPONSE_KEY"


RESPONSE_KEY_OPERATIONS_V1 = (
    ResponseKeyOperation.CREATE_AND_ENCRYPT_RESPONSE,
    ResponseKeyOperation.VERIFY_RESPONSE_ENVELOPE,
    ResponseKeyOperation.ACTIVATE_RESPONSE_KEY,
    ResponseKeyOperation.ARM_RESPONSE_EXPIRY,
    ResponseKeyOperation.DECRYPT_RESPONSE,
    ResponseKeyOperation.DESTROY_RESPONSE_KEY,
)


@dataclass(frozen=True, slots=True)
class ResponseAeadProfileV1:
    scheme_version: int
    algorithm_id: int
    algorithm: ResponseAeadAlgorithm
    response_dek_size_bytes: int
    nonce_size_bytes: int
    tag_size_bytes: int


@dataclass(frozen=True, slots=True)
class ResponsePlaintextFrameProfileV1:
    scheme_version: int
    content_profile_id: int
    content_profile: ResponseContentProfile
    max_scalar_values: int
    max_utf8_bytes: int
    plaintext_frame_size_bytes: int


@dataclass(frozen=True, slots=True)
class ResponseImmutableContextShapeV1:
    aad_purpose: str
    report_id_size_bytes: int
    response_id_size_bytes: int
    finalization_id_size_bytes: int
    response_key_handle_size_bytes: int


@dataclass(frozen=True, slots=True)
class ResponseCiphertextEnvelopeShapeV1:
    scheme_version: int
    algorithm_id: int
    content_profile_id: int
    nonce_size_bytes: int
    ciphertext_and_tag_size_bytes: int


@dataclass(frozen=True, slots=True)
class ResponseKeyLifecycleProfileV1:
    allowed_operations: tuple[ResponseKeyOperation, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidResponseCryptoProfileV1:
    aead_profile: ResponseAeadProfileV1
    plaintext_frame_profile: ResponsePlaintextFrameProfileV1
    immutable_context_shape: ResponseImmutableContextShapeV1
    ciphertext_envelope_shape: ResponseCiphertextEnvelopeShapeV1
    key_lifecycle_profile: ResponseKeyLifecycleProfileV1

    @property
    def encrypts_response(self) -> bool:
        return False

    @property
    def decrypts_response(self) -> bool:
        return False

    @property
    def exposes_response_dek(self) -> bool:
        return False

    @property
    def stores_plaintext_response(self) -> bool:
        return False

    @property
    def authorizes_response_use(self) -> bool:
        return False


def _reject() -> Never:
    raise ResponseCryptoDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_string_exact(value: object, *, expected: str) -> str:
    if type(value) is not str or value != expected:
        _reject()
    return value


def _require_aead_algorithm(value: object) -> ResponseAeadAlgorithm:
    if isinstance(value, ResponseAeadAlgorithm):
        if value == ResponseAeadAlgorithm.XCHACHA20_POLY1305_IETF:
            return value
        _reject()
    if type(value) is str:
        if value == ResponseAeadAlgorithm.XCHACHA20_POLY1305_IETF.value:
            return ResponseAeadAlgorithm.XCHACHA20_POLY1305_IETF
    _reject()


def _require_content_profile(value: object) -> ResponseContentProfile:
    if isinstance(value, ResponseContentProfile):
        if value == ResponseContentProfile.CANONICAL_UTF8_FIXED_FRAME:
            return value
        _reject()
    if type(value) is str:
        if value == ResponseContentProfile.CANONICAL_UTF8_FIXED_FRAME.value:
            return ResponseContentProfile.CANONICAL_UTF8_FIXED_FRAME
    _reject()


def _require_operation(value: object) -> ResponseKeyOperation:
    if isinstance(value, ResponseKeyOperation):
        return value
    _reject()


def _require_operation_sequence(
    value: object,
) -> tuple[ResponseKeyOperation, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_operation(operation) for operation in value)
    if normalized != RESPONSE_KEY_OPERATIONS_V1:
        _reject()
    return normalized


def validate_response_aead_profile_v1(
    profile: ResponseAeadProfileV1,
) -> ResponseAeadProfileV1:
    if type(profile) is not ResponseAeadProfileV1:
        _reject()
    return ResponseAeadProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        ),
        algorithm_id=_require_uint_exact(
            profile.algorithm_id,
            expected=RESPONSE_AEAD_ALGORITHM_ID,
        ),
        algorithm=_require_aead_algorithm(profile.algorithm),
        response_dek_size_bytes=_require_uint_exact(
            profile.response_dek_size_bytes,
            expected=RESPONSE_DEK_BYTES,
        ),
        nonce_size_bytes=_require_uint_exact(
            profile.nonce_size_bytes,
            expected=RESPONSE_NONCE_BYTES,
        ),
        tag_size_bytes=_require_uint_exact(
            profile.tag_size_bytes,
            expected=RESPONSE_AEAD_TAG_BYTES,
        ),
    )


def validate_response_plaintext_frame_profile_v1(
    profile: ResponsePlaintextFrameProfileV1,
) -> ResponsePlaintextFrameProfileV1:
    if type(profile) is not ResponsePlaintextFrameProfileV1:
        _reject()
    return ResponsePlaintextFrameProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        ),
        content_profile_id=_require_uint_exact(
            profile.content_profile_id,
            expected=RESPONSE_CONTENT_PROFILE_ID,
        ),
        content_profile=_require_content_profile(profile.content_profile),
        max_scalar_values=_require_uint_exact(
            profile.max_scalar_values,
            expected=RESPONSE_MAX_SCALAR_VALUES,
        ),
        max_utf8_bytes=_require_uint_exact(
            profile.max_utf8_bytes,
            expected=RESPONSE_MAX_UTF8_BYTES,
        ),
        plaintext_frame_size_bytes=_require_uint_exact(
            profile.plaintext_frame_size_bytes,
            expected=RESPONSE_PLAINTEXT_FRAME_BYTES,
        ),
    )


def validate_response_immutable_context_shape_v1(
    shape: ResponseImmutableContextShapeV1,
) -> ResponseImmutableContextShapeV1:
    if type(shape) is not ResponseImmutableContextShapeV1:
        _reject()
    return ResponseImmutableContextShapeV1(
        aad_purpose=_require_string_exact(
            shape.aad_purpose,
            expected=RESPONSE_AAD_PURPOSE,
        ),
        report_id_size_bytes=_require_uint_exact(
            shape.report_id_size_bytes,
            expected=RESPONSE_REPORT_ID_BYTES,
        ),
        response_id_size_bytes=_require_uint_exact(
            shape.response_id_size_bytes,
            expected=RESPONSE_ID_BYTES,
        ),
        finalization_id_size_bytes=_require_uint_exact(
            shape.finalization_id_size_bytes,
            expected=RESPONSE_FINALIZATION_ID_BYTES,
        ),
        response_key_handle_size_bytes=_require_uint_exact(
            shape.response_key_handle_size_bytes,
            expected=RESPONSE_KEY_HANDLE_BYTES,
        ),
    )


def validate_response_ciphertext_envelope_shape_v1(
    shape: ResponseCiphertextEnvelopeShapeV1,
) -> ResponseCiphertextEnvelopeShapeV1:
    if type(shape) is not ResponseCiphertextEnvelopeShapeV1:
        _reject()
    return ResponseCiphertextEnvelopeShapeV1(
        scheme_version=_require_uint_exact(
            shape.scheme_version,
            expected=RESPONSE_CRYPTO_PROTOCOL_VERSION,
        ),
        algorithm_id=_require_uint_exact(
            shape.algorithm_id,
            expected=RESPONSE_AEAD_ALGORITHM_ID,
        ),
        content_profile_id=_require_uint_exact(
            shape.content_profile_id,
            expected=RESPONSE_CONTENT_PROFILE_ID,
        ),
        nonce_size_bytes=_require_uint_exact(
            shape.nonce_size_bytes,
            expected=RESPONSE_NONCE_BYTES,
        ),
        ciphertext_and_tag_size_bytes=_require_uint_exact(
            shape.ciphertext_and_tag_size_bytes,
            expected=RESPONSE_CIPHERTEXT_AND_TAG_BYTES,
        ),
    )


def validate_response_key_lifecycle_profile_v1(
    profile: ResponseKeyLifecycleProfileV1,
) -> ResponseKeyLifecycleProfileV1:
    if type(profile) is not ResponseKeyLifecycleProfileV1:
        _reject()
    return ResponseKeyLifecycleProfileV1(
        allowed_operations=_require_operation_sequence(
            profile.allowed_operations
        ),
    )


def validate_response_crypto_profile_v1(
    *,
    aead_profile: ResponseAeadProfileV1,
    plaintext_frame_profile: ResponsePlaintextFrameProfileV1,
    immutable_context_shape: ResponseImmutableContextShapeV1,
    ciphertext_envelope_shape: ResponseCiphertextEnvelopeShapeV1,
    key_lifecycle_profile: ResponseKeyLifecycleProfileV1,
) -> StructurallyValidResponseCryptoProfileV1:
    """Validate only exact v1 metadata shapes; never authorize use."""

    return StructurallyValidResponseCryptoProfileV1(
        aead_profile=validate_response_aead_profile_v1(aead_profile),
        plaintext_frame_profile=validate_response_plaintext_frame_profile_v1(
            plaintext_frame_profile
        ),
        immutable_context_shape=validate_response_immutable_context_shape_v1(
            immutable_context_shape
        ),
        ciphertext_envelope_shape=(
            validate_response_ciphertext_envelope_shape_v1(
                ciphertext_envelope_shape
            )
        ),
        key_lifecycle_profile=validate_response_key_lifecycle_profile_v1(
            key_lifecycle_profile
        ),
    )
