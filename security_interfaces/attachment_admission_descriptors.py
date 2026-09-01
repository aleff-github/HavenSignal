"""Inert attachment admission descriptors for the common v1 file profile.

This module validates only static attachment metadata. It does not inspect file
bytes, trust filenames or MIME types, parse formats, create sandbox jobs,
persist originals, log request material, or authorize uploads.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import AttachmentAdmissionDescriptorRejected


ATTACHMENT_ADMISSION_PROTOCOL_VERSION = 1
ATTACHMENT_FILE_MIN_BYTES = 1
ATTACHMENT_FILE_MAX_BYTES = 5_242_880
ATTACHMENT_PDF_SLOTS_MAX = 1
ATTACHMENT_IMAGE_SLOTS_MAX = 3
ATTACHMENT_TOTAL_SLOTS_MAX = 4
ATTACHMENT_FILENAME_MIN_STEM_LENGTH = 1
ATTACHMENT_FILENAME_MAX_STEM_LENGTH = 64
ATTACHMENT_FILENAME_PATTERN = r"^[A-Za-z]{1,64}\.(pdf|jpg|jpeg|png)$"


class AttachmentKind(StrEnum):
    PDF = "PDF"
    JPEG = "JPEG"
    PNG = "PNG"


class AttachmentSlot(StrEnum):
    PDF = "PDF"
    IMAGE_1 = "IMAGE_1"
    IMAGE_2 = "IMAGE_2"
    IMAGE_3 = "IMAGE_3"


class AttachmentExtension(StrEnum):
    PDF = "pdf"
    JPG = "jpg"
    JPEG = "jpeg"
    PNG = "png"


ATTACHMENT_KINDS_V1 = (
    AttachmentKind.PDF,
    AttachmentKind.JPEG,
    AttachmentKind.PNG,
)
ATTACHMENT_SLOTS_V1 = (
    AttachmentSlot.PDF,
    AttachmentSlot.IMAGE_1,
    AttachmentSlot.IMAGE_2,
    AttachmentSlot.IMAGE_3,
)
ATTACHMENT_EXTENSIONS_V1 = (
    AttachmentExtension.PDF,
    AttachmentExtension.JPG,
    AttachmentExtension.JPEG,
    AttachmentExtension.PNG,
)


@dataclass(frozen=True, slots=True)
class AttachmentCountLimitProfileV1:
    pdf_slots_max: int
    image_slots_max: int
    total_slots_max: int


@dataclass(frozen=True, slots=True)
class AttachmentByteLimitProfileV1:
    file_min_bytes: int
    file_max_bytes: int


@dataclass(frozen=True, slots=True)
class AttachmentKindProfileV1:
    allowed_kinds: tuple[AttachmentKind, ...]
    allowed_slots: tuple[AttachmentSlot, ...]
    allowed_extensions: tuple[AttachmentExtension, ...]


@dataclass(frozen=True, slots=True)
class AttachmentFilenameProfileV1:
    filename_pattern: str
    stem_min_length: int
    stem_max_length: int
    filename_is_storage_input: bool
    filename_is_loggable: bool
    filename_is_authoritative_kind: bool


@dataclass(frozen=True, slots=True)
class AttachmentTrustProfileV1:
    client_content_type_trusted: bool
    content_disposition_trusted: bool
    path_trusted: bool
    extension_trusted: bool
    magic_bytes_sufficient: bool
    parser_warning_accepted: bool
    partial_success_accepted: bool


@dataclass(frozen=True, slots=True)
class AttachmentAdmissionProfileV1:
    scheme_version: int
    count_limits: AttachmentCountLimitProfileV1
    byte_limits: AttachmentByteLimitProfileV1
    kind_profile: AttachmentKindProfileV1
    filename_profile: AttachmentFilenameProfileV1
    trust_profile: AttachmentTrustProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidAttachmentAdmissionProfileV1:
    profile: AttachmentAdmissionProfileV1

    @property
    def inspects_file_bytes(self) -> bool:
        return False

    @property
    def parses_file_format(self) -> bool:
        return False

    @property
    def creates_sandbox_job(self) -> bool:
        return False

    @property
    def persists_original_bytes(self) -> bool:
        return False

    @property
    def persists_original_filename(self) -> bool:
        return False

    @property
    def logs_request_material(self) -> bool:
        return False

    @property
    def authorizes_upload(self) -> bool:
        return False


def _reject() -> Never:
    raise AttachmentAdmissionDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_string_exact(value: object, *, expected: str) -> str:
    if type(value) is not str or value != expected:
        _reject()
    return value


def _require_kind(value: object) -> AttachmentKind:
    if isinstance(value, AttachmentKind):
        return value
    if type(value) is str:
        for kind in AttachmentKind:
            if value == kind.value:
                return kind
    _reject()


def _require_slot(value: object) -> AttachmentSlot:
    if isinstance(value, AttachmentSlot):
        return value
    if type(value) is str:
        for slot in AttachmentSlot:
            if value == slot.value:
                return slot
    _reject()


def _require_extension(value: object) -> AttachmentExtension:
    if isinstance(value, AttachmentExtension):
        return value
    if type(value) is str:
        for extension in AttachmentExtension:
            if value == extension.value:
                return extension
    _reject()


def _require_kinds(value: object) -> tuple[AttachmentKind, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_kind(kind) for kind in value)
    if normalized != ATTACHMENT_KINDS_V1:
        _reject()
    return normalized


def _require_slots(value: object) -> tuple[AttachmentSlot, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_slot(slot) for slot in value)
    if normalized != ATTACHMENT_SLOTS_V1:
        _reject()
    return normalized


def _require_extensions(
    value: object,
) -> tuple[AttachmentExtension, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_extension(extension) for extension in value
    )
    if normalized != ATTACHMENT_EXTENSIONS_V1:
        _reject()
    return normalized


def validate_attachment_count_limit_profile_v1(
    profile: AttachmentCountLimitProfileV1,
) -> AttachmentCountLimitProfileV1:
    if type(profile) is not AttachmentCountLimitProfileV1:
        _reject()
    return AttachmentCountLimitProfileV1(
        pdf_slots_max=_require_uint_exact(
            profile.pdf_slots_max,
            expected=ATTACHMENT_PDF_SLOTS_MAX,
        ),
        image_slots_max=_require_uint_exact(
            profile.image_slots_max,
            expected=ATTACHMENT_IMAGE_SLOTS_MAX,
        ),
        total_slots_max=_require_uint_exact(
            profile.total_slots_max,
            expected=ATTACHMENT_TOTAL_SLOTS_MAX,
        ),
    )


def validate_attachment_byte_limit_profile_v1(
    profile: AttachmentByteLimitProfileV1,
) -> AttachmentByteLimitProfileV1:
    if type(profile) is not AttachmentByteLimitProfileV1:
        _reject()
    return AttachmentByteLimitProfileV1(
        file_min_bytes=_require_uint_exact(
            profile.file_min_bytes,
            expected=ATTACHMENT_FILE_MIN_BYTES,
        ),
        file_max_bytes=_require_uint_exact(
            profile.file_max_bytes,
            expected=ATTACHMENT_FILE_MAX_BYTES,
        ),
    )


def validate_attachment_kind_profile_v1(
    profile: AttachmentKindProfileV1,
) -> AttachmentKindProfileV1:
    if type(profile) is not AttachmentKindProfileV1:
        _reject()
    return AttachmentKindProfileV1(
        allowed_kinds=_require_kinds(profile.allowed_kinds),
        allowed_slots=_require_slots(profile.allowed_slots),
        allowed_extensions=_require_extensions(profile.allowed_extensions),
    )


def validate_attachment_filename_profile_v1(
    profile: AttachmentFilenameProfileV1,
) -> AttachmentFilenameProfileV1:
    if type(profile) is not AttachmentFilenameProfileV1:
        _reject()
    return AttachmentFilenameProfileV1(
        filename_pattern=_require_string_exact(
            profile.filename_pattern,
            expected=ATTACHMENT_FILENAME_PATTERN,
        ),
        stem_min_length=_require_uint_exact(
            profile.stem_min_length,
            expected=ATTACHMENT_FILENAME_MIN_STEM_LENGTH,
        ),
        stem_max_length=_require_uint_exact(
            profile.stem_max_length,
            expected=ATTACHMENT_FILENAME_MAX_STEM_LENGTH,
        ),
        filename_is_storage_input=_require_bool_exact(
            profile.filename_is_storage_input,
            expected=False,
        ),
        filename_is_loggable=_require_bool_exact(
            profile.filename_is_loggable,
            expected=False,
        ),
        filename_is_authoritative_kind=_require_bool_exact(
            profile.filename_is_authoritative_kind,
            expected=False,
        ),
    )


def validate_attachment_trust_profile_v1(
    profile: AttachmentTrustProfileV1,
) -> AttachmentTrustProfileV1:
    if type(profile) is not AttachmentTrustProfileV1:
        _reject()
    return AttachmentTrustProfileV1(
        client_content_type_trusted=_require_bool_exact(
            profile.client_content_type_trusted,
            expected=False,
        ),
        content_disposition_trusted=_require_bool_exact(
            profile.content_disposition_trusted,
            expected=False,
        ),
        path_trusted=_require_bool_exact(
            profile.path_trusted,
            expected=False,
        ),
        extension_trusted=_require_bool_exact(
            profile.extension_trusted,
            expected=False,
        ),
        magic_bytes_sufficient=_require_bool_exact(
            profile.magic_bytes_sufficient,
            expected=False,
        ),
        parser_warning_accepted=_require_bool_exact(
            profile.parser_warning_accepted,
            expected=False,
        ),
        partial_success_accepted=_require_bool_exact(
            profile.partial_success_accepted,
            expected=False,
        ),
    )


def validate_attachment_admission_profile_v1(
    profile: AttachmentAdmissionProfileV1,
) -> StructurallyValidAttachmentAdmissionProfileV1:
    if type(profile) is not AttachmentAdmissionProfileV1:
        _reject()
    normalized = AttachmentAdmissionProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=ATTACHMENT_ADMISSION_PROTOCOL_VERSION,
        ),
        count_limits=validate_attachment_count_limit_profile_v1(
            profile.count_limits
        ),
        byte_limits=validate_attachment_byte_limit_profile_v1(
            profile.byte_limits
        ),
        kind_profile=validate_attachment_kind_profile_v1(
            profile.kind_profile
        ),
        filename_profile=validate_attachment_filename_profile_v1(
            profile.filename_profile
        ),
        trust_profile=validate_attachment_trust_profile_v1(
            profile.trust_profile
        ),
    )
    return StructurallyValidAttachmentAdmissionProfileV1(profile=normalized)


def expected_attachment_admission_profile_v1() -> AttachmentAdmissionProfileV1:
    """Return only the approved common attachment-admission metadata."""

    return AttachmentAdmissionProfileV1(
        scheme_version=ATTACHMENT_ADMISSION_PROTOCOL_VERSION,
        count_limits=AttachmentCountLimitProfileV1(
            pdf_slots_max=ATTACHMENT_PDF_SLOTS_MAX,
            image_slots_max=ATTACHMENT_IMAGE_SLOTS_MAX,
            total_slots_max=ATTACHMENT_TOTAL_SLOTS_MAX,
        ),
        byte_limits=AttachmentByteLimitProfileV1(
            file_min_bytes=ATTACHMENT_FILE_MIN_BYTES,
            file_max_bytes=ATTACHMENT_FILE_MAX_BYTES,
        ),
        kind_profile=AttachmentKindProfileV1(
            allowed_kinds=ATTACHMENT_KINDS_V1,
            allowed_slots=ATTACHMENT_SLOTS_V1,
            allowed_extensions=ATTACHMENT_EXTENSIONS_V1,
        ),
        filename_profile=AttachmentFilenameProfileV1(
            filename_pattern=ATTACHMENT_FILENAME_PATTERN,
            stem_min_length=ATTACHMENT_FILENAME_MIN_STEM_LENGTH,
            stem_max_length=ATTACHMENT_FILENAME_MAX_STEM_LENGTH,
            filename_is_storage_input=False,
            filename_is_loggable=False,
            filename_is_authoritative_kind=False,
        ),
        trust_profile=AttachmentTrustProfileV1(
            client_content_type_trusted=False,
            content_disposition_trusted=False,
            path_trusted=False,
            extension_trusted=False,
            magic_bytes_sufficient=False,
            parser_warning_accepted=False,
            partial_success_accepted=False,
        ),
    )
