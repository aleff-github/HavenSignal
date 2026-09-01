"""Inert original-report crypto descriptors from the approved v1 profile.

This module validates only static cryptographic profile shapes. It does not
canonicalize report text, frame plaintext, derive subkeys, create nonces,
encrypt, decrypt, parse envelopes, produce AAD, call a Key Service, stream
attachments, hold key handles, store ciphertext, or authorize report use.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import ReportCryptoDescriptorRejected


REPORT_CRYPTO_PROTOCOL_VERSION = 1
REPORT_AEAD_ALGORITHM_ID = 1
REPORT_CONTENT_PROFILE_ID = 1
REPORT_AAD_PURPOSE = "ORIGINAL_REPORT_OBJECT"
REPORT_OBJECT_SUBKEY_PURPOSE = "REPORT_OBJECT_AEAD_SUBKEY"

REPORT_DEK_BYTES = 32
REPORT_OBJECT_SUBKEY_BYTES = 32
REPORT_NONCE_BYTES = 24
REPORT_AEAD_TAG_BYTES = 16

REPORT_ID_BYTES = 16
REPORT_ATTEMPT_ID_BYTES = 16
REPORT_OBJECT_ID_BYTES = 16
REPORT_KEY_HANDLE_BYTES = 32

REPORT_MAX_SCALAR_VALUES = 5_000
REPORT_MAX_UTF8_BYTES = 20_000
REPORT_TEXT_PLAINTEXT_FRAME_BYTES = 20_005
REPORT_ATTACHMENT_MAX_BYTES = 5_242_880
REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES = 5_242_890
REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES = 20_021
REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES = 5_242_906

REPORT_TEXT_OBJECT_SLOT = 0
REPORT_PDF_OBJECT_SLOT = 1
REPORT_IMAGE_OBJECT_SLOT_MIN = 2
REPORT_IMAGE_OBJECT_SLOT_MAX = 4


class ReportAeadAlgorithm(StrEnum):
    XCHACHA20_POLY1305_IETF = "XCHACHA20_POLY1305_IETF"


class ReportContentProfile(StrEnum):
    CANONICAL_FIXED_FRAME = "CANONICAL_FIXED_FRAME"


class ReportObjectKind(StrEnum):
    REPORT_TEXT = "REPORT_TEXT"
    PDF = "PDF"
    JPEG = "JPEG"
    PNG = "PNG"


class ReportKeyOperation(StrEnum):
    CREATE_REPORT_KEY = "CREATE_REPORT_KEY"
    ENCRYPT_NEW_REPORT_OBJECT = "ENCRYPT_NEW_REPORT_OBJECT"
    VERIFY_REPORT_ENVELOPE = "VERIFY_REPORT_ENVELOPE"
    ACTIVATE_REPORT_KEY = "ACTIVATE_REPORT_KEY"
    DECRYPT_REPORT_TEXT = "DECRYPT_REPORT_TEXT"
    STREAM_ATTACHMENT_TO_SANDBOX = "STREAM_ATTACHMENT_TO_SANDBOX"
    DESTROY_REPORT_KEY = "DESTROY_REPORT_KEY"


REPORT_OBJECT_KINDS_V1 = (
    ReportObjectKind.REPORT_TEXT,
    ReportObjectKind.PDF,
    ReportObjectKind.JPEG,
    ReportObjectKind.PNG,
)

REPORT_KEY_OPERATIONS_V1 = (
    ReportKeyOperation.CREATE_REPORT_KEY,
    ReportKeyOperation.ENCRYPT_NEW_REPORT_OBJECT,
    ReportKeyOperation.VERIFY_REPORT_ENVELOPE,
    ReportKeyOperation.ACTIVATE_REPORT_KEY,
    ReportKeyOperation.DECRYPT_REPORT_TEXT,
    ReportKeyOperation.STREAM_ATTACHMENT_TO_SANDBOX,
    ReportKeyOperation.DESTROY_REPORT_KEY,
)


@dataclass(frozen=True, slots=True)
class ReportAeadProfileV1:
    scheme_version: int
    algorithm_id: int
    algorithm: ReportAeadAlgorithm
    report_dek_size_bytes: int
    object_subkey_size_bytes: int
    nonce_size_bytes: int
    tag_size_bytes: int


@dataclass(frozen=True, slots=True)
class ReportPlaintextFrameProfileV1:
    scheme_version: int
    content_profile_id: int
    content_profile: ReportContentProfile
    max_scalar_values: int
    max_utf8_bytes: int
    text_plaintext_frame_size_bytes: int
    attachment_max_bytes: int
    attachment_plaintext_frame_size_bytes: int


@dataclass(frozen=True, slots=True)
class ReportObjectKindProfileV1:
    object_kinds: tuple[ReportObjectKind, ...]
    text_object_slot: int
    pdf_object_slot: int
    image_object_slot_min: int
    image_object_slot_max: int


@dataclass(frozen=True, slots=True)
class ReportImmutableContextShapeV1:
    aad_purpose: str
    object_subkey_purpose: str
    report_id_size_bytes: int
    attempt_id_size_bytes: int
    object_id_size_bytes: int
    report_key_handle_size_bytes: int


@dataclass(frozen=True, slots=True)
class ReportCiphertextEnvelopeShapeV1:
    scheme_version: int
    algorithm_id: int
    content_profile_id: int
    nonce_size_bytes: int
    text_ciphertext_and_tag_size_bytes: int
    attachment_ciphertext_and_tag_size_bytes: int


@dataclass(frozen=True, slots=True)
class ReportKeyLifecycleProfileV1:
    allowed_operations: tuple[ReportKeyOperation, ...]


@dataclass(frozen=True, slots=True)
class StructurallyValidReportCryptoProfileV1:
    aead_profile: ReportAeadProfileV1
    plaintext_frame_profile: ReportPlaintextFrameProfileV1
    object_kind_profile: ReportObjectKindProfileV1
    immutable_context_shape: ReportImmutableContextShapeV1
    ciphertext_envelope_shape: ReportCiphertextEnvelopeShapeV1
    key_lifecycle_profile: ReportKeyLifecycleProfileV1

    @property
    def generates_report_dek(self) -> bool:
        return False

    @property
    def derives_object_subkeys(self) -> bool:
        return False

    @property
    def encrypts_report_objects(self) -> bool:
        return False

    @property
    def decrypts_report_text(self) -> bool:
        return False

    @property
    def streams_original_attachments(self) -> bool:
        return False

    @property
    def exposes_report_dek(self) -> bool:
        return False

    @property
    def stores_plaintext_report(self) -> bool:
        return False

    @property
    def authorizes_report_use(self) -> bool:
        return False


def _reject() -> Never:
    raise ReportCryptoDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_string_exact(value: object, *, expected: str) -> str:
    if type(value) is not str or value != expected:
        _reject()
    return value


def _require_aead_algorithm(value: object) -> ReportAeadAlgorithm:
    if isinstance(value, ReportAeadAlgorithm):
        if value == ReportAeadAlgorithm.XCHACHA20_POLY1305_IETF:
            return value
        _reject()
    if type(value) is str:
        if value == ReportAeadAlgorithm.XCHACHA20_POLY1305_IETF.value:
            return ReportAeadAlgorithm.XCHACHA20_POLY1305_IETF
    _reject()


def _require_content_profile(value: object) -> ReportContentProfile:
    if isinstance(value, ReportContentProfile):
        if value == ReportContentProfile.CANONICAL_FIXED_FRAME:
            return value
        _reject()
    if type(value) is str:
        if value == ReportContentProfile.CANONICAL_FIXED_FRAME.value:
            return ReportContentProfile.CANONICAL_FIXED_FRAME
    _reject()


def _require_object_kind(value: object) -> ReportObjectKind:
    if isinstance(value, ReportObjectKind):
        return value
    _reject()


def _require_object_kind_sequence(
    value: object,
) -> tuple[ReportObjectKind, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_object_kind(kind) for kind in value)
    if normalized != REPORT_OBJECT_KINDS_V1:
        _reject()
    return normalized


def _require_operation(value: object) -> ReportKeyOperation:
    if isinstance(value, ReportKeyOperation):
        return value
    _reject()


def _require_operation_sequence(
    value: object,
) -> tuple[ReportKeyOperation, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_operation(operation) for operation in value)
    if normalized != REPORT_KEY_OPERATIONS_V1:
        _reject()
    return normalized


def validate_report_aead_profile_v1(
    profile: ReportAeadProfileV1,
) -> ReportAeadProfileV1:
    if type(profile) is not ReportAeadProfileV1:
        _reject()
    return ReportAeadProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=REPORT_CRYPTO_PROTOCOL_VERSION,
        ),
        algorithm_id=_require_uint_exact(
            profile.algorithm_id,
            expected=REPORT_AEAD_ALGORITHM_ID,
        ),
        algorithm=_require_aead_algorithm(profile.algorithm),
        report_dek_size_bytes=_require_uint_exact(
            profile.report_dek_size_bytes,
            expected=REPORT_DEK_BYTES,
        ),
        object_subkey_size_bytes=_require_uint_exact(
            profile.object_subkey_size_bytes,
            expected=REPORT_OBJECT_SUBKEY_BYTES,
        ),
        nonce_size_bytes=_require_uint_exact(
            profile.nonce_size_bytes,
            expected=REPORT_NONCE_BYTES,
        ),
        tag_size_bytes=_require_uint_exact(
            profile.tag_size_bytes,
            expected=REPORT_AEAD_TAG_BYTES,
        ),
    )


def validate_report_plaintext_frame_profile_v1(
    profile: ReportPlaintextFrameProfileV1,
) -> ReportPlaintextFrameProfileV1:
    if type(profile) is not ReportPlaintextFrameProfileV1:
        _reject()
    return ReportPlaintextFrameProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=REPORT_CRYPTO_PROTOCOL_VERSION,
        ),
        content_profile_id=_require_uint_exact(
            profile.content_profile_id,
            expected=REPORT_CONTENT_PROFILE_ID,
        ),
        content_profile=_require_content_profile(profile.content_profile),
        max_scalar_values=_require_uint_exact(
            profile.max_scalar_values,
            expected=REPORT_MAX_SCALAR_VALUES,
        ),
        max_utf8_bytes=_require_uint_exact(
            profile.max_utf8_bytes,
            expected=REPORT_MAX_UTF8_BYTES,
        ),
        text_plaintext_frame_size_bytes=_require_uint_exact(
            profile.text_plaintext_frame_size_bytes,
            expected=REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
        ),
        attachment_max_bytes=_require_uint_exact(
            profile.attachment_max_bytes,
            expected=REPORT_ATTACHMENT_MAX_BYTES,
        ),
        attachment_plaintext_frame_size_bytes=_require_uint_exact(
            profile.attachment_plaintext_frame_size_bytes,
            expected=REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES,
        ),
    )


def validate_report_object_kind_profile_v1(
    profile: ReportObjectKindProfileV1,
) -> ReportObjectKindProfileV1:
    if type(profile) is not ReportObjectKindProfileV1:
        _reject()
    return ReportObjectKindProfileV1(
        object_kinds=_require_object_kind_sequence(profile.object_kinds),
        text_object_slot=_require_uint_exact(
            profile.text_object_slot,
            expected=REPORT_TEXT_OBJECT_SLOT,
        ),
        pdf_object_slot=_require_uint_exact(
            profile.pdf_object_slot,
            expected=REPORT_PDF_OBJECT_SLOT,
        ),
        image_object_slot_min=_require_uint_exact(
            profile.image_object_slot_min,
            expected=REPORT_IMAGE_OBJECT_SLOT_MIN,
        ),
        image_object_slot_max=_require_uint_exact(
            profile.image_object_slot_max,
            expected=REPORT_IMAGE_OBJECT_SLOT_MAX,
        ),
    )


def validate_report_immutable_context_shape_v1(
    shape: ReportImmutableContextShapeV1,
) -> ReportImmutableContextShapeV1:
    if type(shape) is not ReportImmutableContextShapeV1:
        _reject()
    return ReportImmutableContextShapeV1(
        aad_purpose=_require_string_exact(
            shape.aad_purpose,
            expected=REPORT_AAD_PURPOSE,
        ),
        object_subkey_purpose=_require_string_exact(
            shape.object_subkey_purpose,
            expected=REPORT_OBJECT_SUBKEY_PURPOSE,
        ),
        report_id_size_bytes=_require_uint_exact(
            shape.report_id_size_bytes,
            expected=REPORT_ID_BYTES,
        ),
        attempt_id_size_bytes=_require_uint_exact(
            shape.attempt_id_size_bytes,
            expected=REPORT_ATTEMPT_ID_BYTES,
        ),
        object_id_size_bytes=_require_uint_exact(
            shape.object_id_size_bytes,
            expected=REPORT_OBJECT_ID_BYTES,
        ),
        report_key_handle_size_bytes=_require_uint_exact(
            shape.report_key_handle_size_bytes,
            expected=REPORT_KEY_HANDLE_BYTES,
        ),
    )


def validate_report_ciphertext_envelope_shape_v1(
    shape: ReportCiphertextEnvelopeShapeV1,
) -> ReportCiphertextEnvelopeShapeV1:
    if type(shape) is not ReportCiphertextEnvelopeShapeV1:
        _reject()
    return ReportCiphertextEnvelopeShapeV1(
        scheme_version=_require_uint_exact(
            shape.scheme_version,
            expected=REPORT_CRYPTO_PROTOCOL_VERSION,
        ),
        algorithm_id=_require_uint_exact(
            shape.algorithm_id,
            expected=REPORT_AEAD_ALGORITHM_ID,
        ),
        content_profile_id=_require_uint_exact(
            shape.content_profile_id,
            expected=REPORT_CONTENT_PROFILE_ID,
        ),
        nonce_size_bytes=_require_uint_exact(
            shape.nonce_size_bytes,
            expected=REPORT_NONCE_BYTES,
        ),
        text_ciphertext_and_tag_size_bytes=_require_uint_exact(
            shape.text_ciphertext_and_tag_size_bytes,
            expected=REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES,
        ),
        attachment_ciphertext_and_tag_size_bytes=_require_uint_exact(
            shape.attachment_ciphertext_and_tag_size_bytes,
            expected=REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES,
        ),
    )


def validate_report_key_lifecycle_profile_v1(
    profile: ReportKeyLifecycleProfileV1,
) -> ReportKeyLifecycleProfileV1:
    if type(profile) is not ReportKeyLifecycleProfileV1:
        _reject()
    return ReportKeyLifecycleProfileV1(
        allowed_operations=_require_operation_sequence(
            profile.allowed_operations
        ),
    )


def validate_report_crypto_profile_v1(
    *,
    aead_profile: ReportAeadProfileV1,
    plaintext_frame_profile: ReportPlaintextFrameProfileV1,
    object_kind_profile: ReportObjectKindProfileV1,
    immutable_context_shape: ReportImmutableContextShapeV1,
    ciphertext_envelope_shape: ReportCiphertextEnvelopeShapeV1,
    key_lifecycle_profile: ReportKeyLifecycleProfileV1,
) -> StructurallyValidReportCryptoProfileV1:
    """Validate only exact v1 metadata shapes; never authorize use."""

    return StructurallyValidReportCryptoProfileV1(
        aead_profile=validate_report_aead_profile_v1(aead_profile),
        plaintext_frame_profile=validate_report_plaintext_frame_profile_v1(
            plaintext_frame_profile
        ),
        object_kind_profile=validate_report_object_kind_profile_v1(
            object_kind_profile
        ),
        immutable_context_shape=validate_report_immutable_context_shape_v1(
            immutable_context_shape
        ),
        ciphertext_envelope_shape=validate_report_ciphertext_envelope_shape_v1(
            ciphertext_envelope_shape
        ),
        key_lifecycle_profile=validate_report_key_lifecycle_profile_v1(
            key_lifecycle_profile
        ),
    )


def expected_report_crypto_profile_v1() -> StructurallyValidReportCryptoProfileV1:
    """Return the exact inert original-report crypto profile."""

    return validate_report_crypto_profile_v1(
        aead_profile=ReportAeadProfileV1(
            scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
            algorithm_id=REPORT_AEAD_ALGORITHM_ID,
            algorithm=ReportAeadAlgorithm.XCHACHA20_POLY1305_IETF,
            report_dek_size_bytes=REPORT_DEK_BYTES,
            object_subkey_size_bytes=REPORT_OBJECT_SUBKEY_BYTES,
            nonce_size_bytes=REPORT_NONCE_BYTES,
            tag_size_bytes=REPORT_AEAD_TAG_BYTES,
        ),
        plaintext_frame_profile=ReportPlaintextFrameProfileV1(
            scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
            content_profile_id=REPORT_CONTENT_PROFILE_ID,
            content_profile=ReportContentProfile.CANONICAL_FIXED_FRAME,
            max_scalar_values=REPORT_MAX_SCALAR_VALUES,
            max_utf8_bytes=REPORT_MAX_UTF8_BYTES,
            text_plaintext_frame_size_bytes=REPORT_TEXT_PLAINTEXT_FRAME_BYTES,
            attachment_max_bytes=REPORT_ATTACHMENT_MAX_BYTES,
            attachment_plaintext_frame_size_bytes=(
                REPORT_ATTACHMENT_PLAINTEXT_FRAME_BYTES
            ),
        ),
        object_kind_profile=ReportObjectKindProfileV1(
            object_kinds=REPORT_OBJECT_KINDS_V1,
            text_object_slot=REPORT_TEXT_OBJECT_SLOT,
            pdf_object_slot=REPORT_PDF_OBJECT_SLOT,
            image_object_slot_min=REPORT_IMAGE_OBJECT_SLOT_MIN,
            image_object_slot_max=REPORT_IMAGE_OBJECT_SLOT_MAX,
        ),
        immutable_context_shape=ReportImmutableContextShapeV1(
            aad_purpose=REPORT_AAD_PURPOSE,
            object_subkey_purpose=REPORT_OBJECT_SUBKEY_PURPOSE,
            report_id_size_bytes=REPORT_ID_BYTES,
            attempt_id_size_bytes=REPORT_ATTEMPT_ID_BYTES,
            object_id_size_bytes=REPORT_OBJECT_ID_BYTES,
            report_key_handle_size_bytes=REPORT_KEY_HANDLE_BYTES,
        ),
        ciphertext_envelope_shape=ReportCiphertextEnvelopeShapeV1(
            scheme_version=REPORT_CRYPTO_PROTOCOL_VERSION,
            algorithm_id=REPORT_AEAD_ALGORITHM_ID,
            content_profile_id=REPORT_CONTENT_PROFILE_ID,
            nonce_size_bytes=REPORT_NONCE_BYTES,
            text_ciphertext_and_tag_size_bytes=(
                REPORT_TEXT_CIPHERTEXT_AND_TAG_BYTES
            ),
            attachment_ciphertext_and_tag_size_bytes=(
                REPORT_ATTACHMENT_CIPHERTEXT_AND_TAG_BYTES
            ),
        ),
        key_lifecycle_profile=ReportKeyLifecycleProfileV1(
            allowed_operations=REPORT_KEY_OPERATIONS_V1
        ),
    )
