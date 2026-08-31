"""Inert recovery credential descriptors from the owner-approved v1 profile.

This module performs only strict structural encoding checks and returns
content-free shape evidence. It does not generate credentials, compute HMACs,
persist verifier state, compare secrets, call a service, or authorize recovery.
"""

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryDescriptorRejected


RECOVERY_CREDENTIAL_PROTOCOL_VERSION = 1
TICKET_ID_RAW_BYTES = 16
TICKET_ID_ENCODED_LENGTH = 26
RECOVERY_SECRET_RAW_BYTES = 32
RECOVERY_SECRET_ENCODED_LENGTH = 43
RECOVERY_VERIFIER_TAG_BYTES = 32
RECOVERY_VERIFIER_DOMAIN_LABEL = "anonymous-reporting/recovery-verifier/v1"

TICKET_ID_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
RECOVERY_SECRET_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-"
)


class RecoveryCredentialEncoding(StrEnum):
    BASE32_UPPER_UNPADDED = "BASE32_RFC4648_UPPER_UNPADDED"
    BASE64URL_UNPADDED = "BASE64URL_RFC4648_UNPADDED"


class RecoveryCredentialRole(StrEnum):
    PUBLIC_LOOKUP_IDENTIFIER = "PUBLIC_LOOKUP_IDENTIFIER"
    AUTHENTICATION_SECRET = "AUTHENTICATION_SECRET"


@dataclass(frozen=True, slots=True)
class CanonicalTicketIdShapeV1:
    raw_size_bytes: int
    encoded_length: int
    encoding: RecoveryCredentialEncoding
    role: RecoveryCredentialRole


@dataclass(frozen=True, slots=True)
class CanonicalRecoverySecretShapeV1:
    raw_size_bytes: int
    encoded_length: int
    encoding: RecoveryCredentialEncoding
    role: RecoveryCredentialRole


@dataclass(frozen=True, slots=True)
class RecoveryVerifierPurposeProfileV1:
    scheme_version: int
    domain_label: str
    verifier_tag_size_bytes: int


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryCredentialComponentsV1:
    ticket_id_shape: CanonicalTicketIdShapeV1
    recovery_secret_shape: CanonicalRecoverySecretShapeV1
    verifier_profile: RecoveryVerifierPurposeProfileV1

    @property
    def generates_credentials(self) -> bool:
        return False

    @property
    def computes_verifier(self) -> bool:
        return False

    @property
    def stores_plaintext_secret(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_string_exact(value: object, *, expected: str) -> str:
    if type(value) is not str or value != expected:
        _reject()
    return value


def _require_encoding(
    value: object,
    *,
    expected: RecoveryCredentialEncoding,
) -> RecoveryCredentialEncoding:
    if isinstance(value, RecoveryCredentialEncoding):
        if value == expected:
            return value
        _reject()
    if type(value) is str and value == expected.value:
        return expected
    _reject()


def _require_role(
    value: object,
    *,
    expected: RecoveryCredentialRole,
) -> RecoveryCredentialRole:
    if isinstance(value, RecoveryCredentialRole):
        if value == expected:
            return value
        _reject()
    if type(value) is str and value == expected.value:
        return expected
    _reject()


def _require_canonical_text(
    value: object,
    *,
    length: int,
    alphabet: frozenset[str],
) -> str:
    if type(value) is not str or len(value) != length or not value.isascii():
        _reject()
    for character in value:
        if character not in alphabet:
            _reject()
    return value


def validate_ticket_id_text_v1(value: object) -> CanonicalTicketIdShapeV1:
    """Validate strict Ticket ID text and return no credential material."""

    text = _require_canonical_text(
        value,
        length=TICKET_ID_ENCODED_LENGTH,
        alphabet=TICKET_ID_ALPHABET,
    )
    try:
        decoded = base64.b32decode(text + "======", casefold=False)
    except binascii.Error:
        _reject()
    if len(decoded) != TICKET_ID_RAW_BYTES:
        _reject()
    canonical = base64.b32encode(decoded).decode("ascii").rstrip("=")
    if canonical != text:
        _reject()
    return CanonicalTicketIdShapeV1(
        raw_size_bytes=TICKET_ID_RAW_BYTES,
        encoded_length=TICKET_ID_ENCODED_LENGTH,
        encoding=RecoveryCredentialEncoding.BASE32_UPPER_UNPADDED,
        role=RecoveryCredentialRole.PUBLIC_LOOKUP_IDENTIFIER,
    )


def validate_recovery_secret_text_v1(
    value: object,
) -> CanonicalRecoverySecretShapeV1:
    """Validate strict Recovery Secret text and return no secret material."""

    text = _require_canonical_text(
        value,
        length=RECOVERY_SECRET_ENCODED_LENGTH,
        alphabet=RECOVERY_SECRET_ALPHABET,
    )
    try:
        decoded = base64.urlsafe_b64decode(text + "=")
    except (binascii.Error, ValueError):
        _reject()
    if len(decoded) != RECOVERY_SECRET_RAW_BYTES:
        _reject()
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != text:
        _reject()
    return CanonicalRecoverySecretShapeV1(
        raw_size_bytes=RECOVERY_SECRET_RAW_BYTES,
        encoded_length=RECOVERY_SECRET_ENCODED_LENGTH,
        encoding=RecoveryCredentialEncoding.BASE64URL_UNPADDED,
        role=RecoveryCredentialRole.AUTHENTICATION_SECRET,
    )


def validate_ticket_id_shape_v1(
    shape: CanonicalTicketIdShapeV1,
) -> CanonicalTicketIdShapeV1:
    if type(shape) is not CanonicalTicketIdShapeV1:
        _reject()
    return CanonicalTicketIdShapeV1(
        raw_size_bytes=_require_uint_exact(
            shape.raw_size_bytes,
            expected=TICKET_ID_RAW_BYTES,
        ),
        encoded_length=_require_uint_exact(
            shape.encoded_length,
            expected=TICKET_ID_ENCODED_LENGTH,
        ),
        encoding=_require_encoding(
            shape.encoding,
            expected=RecoveryCredentialEncoding.BASE32_UPPER_UNPADDED,
        ),
        role=_require_role(
            shape.role,
            expected=RecoveryCredentialRole.PUBLIC_LOOKUP_IDENTIFIER,
        ),
    )


def validate_recovery_secret_shape_v1(
    shape: CanonicalRecoverySecretShapeV1,
) -> CanonicalRecoverySecretShapeV1:
    if type(shape) is not CanonicalRecoverySecretShapeV1:
        _reject()
    return CanonicalRecoverySecretShapeV1(
        raw_size_bytes=_require_uint_exact(
            shape.raw_size_bytes,
            expected=RECOVERY_SECRET_RAW_BYTES,
        ),
        encoded_length=_require_uint_exact(
            shape.encoded_length,
            expected=RECOVERY_SECRET_ENCODED_LENGTH,
        ),
        encoding=_require_encoding(
            shape.encoding,
            expected=RecoveryCredentialEncoding.BASE64URL_UNPADDED,
        ),
        role=_require_role(
            shape.role,
            expected=RecoveryCredentialRole.AUTHENTICATION_SECRET,
        ),
    )


def validate_recovery_verifier_purpose_profile_v1(
    profile: RecoveryVerifierPurposeProfileV1,
) -> RecoveryVerifierPurposeProfileV1:
    if type(profile) is not RecoveryVerifierPurposeProfileV1:
        _reject()
    return RecoveryVerifierPurposeProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_CREDENTIAL_PROTOCOL_VERSION,
        ),
        domain_label=_require_string_exact(
            profile.domain_label,
            expected=RECOVERY_VERIFIER_DOMAIN_LABEL,
        ),
        verifier_tag_size_bytes=_require_uint_exact(
            profile.verifier_tag_size_bytes,
            expected=RECOVERY_VERIFIER_TAG_BYTES,
        ),
    )


def validate_recovery_credential_components_v1(
    *,
    ticket_id: object,
    recovery_secret: object,
    verifier_profile: RecoveryVerifierPurposeProfileV1,
) -> StructurallyValidRecoveryCredentialComponentsV1:
    """Validate only approved structural shapes; never authorize recovery."""

    return StructurallyValidRecoveryCredentialComponentsV1(
        ticket_id_shape=validate_ticket_id_text_v1(ticket_id),
        recovery_secret_shape=validate_recovery_secret_text_v1(
            recovery_secret
        ),
        verifier_profile=validate_recovery_verifier_purpose_profile_v1(
            verifier_profile
        ),
    )
