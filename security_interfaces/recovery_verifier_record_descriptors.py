"""Inert Recovery Verifier record descriptors from docs/21.

This module validates only static metadata for the persisted verifier-record
shape approved for recovery credentials. It does not persist records, compute
verifiers, test candidate secrets, perform lookups, write a database, expose
endpoints, or authorize recovery.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import RecoveryVerifierRecordDescriptorRejected


RECOVERY_VERIFIER_RECORD_PROFILE_VERSION = 1
RECOVERY_VERIFIER_RECORD_TAG_BYTES = 32


class RecoveryVerifierRecordField(StrEnum):
    SCHEME_VERSION = "SCHEME_VERSION"
    VERIFIER_KEY_ID = "VERIFIER_KEY_ID"
    VERIFIER_TAG = "VERIFIER_TAG"


class RecoveryVerifierRecordRequirement(StrEnum):
    STORED_WITH_PUBLIC_TICKET_ID = "STORED_WITH_PUBLIC_TICKET_ID"
    SERVER_CONTROLLED_KEY_ID = "SERVER_CONTROLLED_KEY_ID"
    KEY_ID_NOT_REPORTER_SUPPLIED = "KEY_ID_NOT_REPORTER_SUPPLIED"
    FULL_LENGTH_TAG = "FULL_LENGTH_TAG"
    NO_SECRET_PLAINTEXT = "NO_SECRET_PLAINTEXT"
    NO_RAW_VERIFICATION_KEY = "NO_RAW_VERIFICATION_KEY"
    DATABASE_ALONE_CANNOT_TEST_SECRET = "DATABASE_ALONE_CANNOT_TEST_SECRET"
    REMOVED_WITH_RECOVERY_STATE = "REMOVED_WITH_RECOVERY_STATE"
    INVALIDATED_AT_RESPONSE_EXPIRY_OR_TERMINAL_DESTRUCTION = (
        "INVALIDATED_AT_RESPONSE_EXPIRY_OR_TERMINAL_DESTRUCTION"
    )


class RecoveryVerifierRecordForbiddenMaterial(StrEnum):
    RECOVERY_SECRET = "RECOVERY_SECRET"
    RAW_VERIFICATION_KEY = "RAW_VERIFICATION_KEY"
    RAW_HMAC_MESSAGE = "RAW_HMAC_MESSAGE"
    REPORT_TEXT = "REPORT_TEXT"
    ATTACHMENT_CONTENT = "ATTACHMENT_CONTENT"
    RESPONSE_DEK = "RESPONSE_DEK"
    REPORT_DEK = "REPORT_DEK"
    OPERATOR_IDENTITY = "OPERATOR_IDENTITY"
    AUDIT_HISTORY_MUTATION_CAPABILITY = "AUDIT_HISTORY_MUTATION_CAPABILITY"


RECOVERY_VERIFIER_RECORD_FIELDS_V1 = (
    RecoveryVerifierRecordField.SCHEME_VERSION,
    RecoveryVerifierRecordField.VERIFIER_KEY_ID,
    RecoveryVerifierRecordField.VERIFIER_TAG,
)

RECOVERY_VERIFIER_RECORD_REQUIREMENTS_V1 = (
    RecoveryVerifierRecordRequirement.STORED_WITH_PUBLIC_TICKET_ID,
    RecoveryVerifierRecordRequirement.SERVER_CONTROLLED_KEY_ID,
    RecoveryVerifierRecordRequirement.KEY_ID_NOT_REPORTER_SUPPLIED,
    RecoveryVerifierRecordRequirement.FULL_LENGTH_TAG,
    RecoveryVerifierRecordRequirement.NO_SECRET_PLAINTEXT,
    RecoveryVerifierRecordRequirement.NO_RAW_VERIFICATION_KEY,
    RecoveryVerifierRecordRequirement.DATABASE_ALONE_CANNOT_TEST_SECRET,
    RecoveryVerifierRecordRequirement.REMOVED_WITH_RECOVERY_STATE,
    (
        RecoveryVerifierRecordRequirement.
        INVALIDATED_AT_RESPONSE_EXPIRY_OR_TERMINAL_DESTRUCTION
    ),
)

RECOVERY_VERIFIER_RECORD_FORBIDDEN_MATERIALS_V1 = (
    RecoveryVerifierRecordForbiddenMaterial.RECOVERY_SECRET,
    RecoveryVerifierRecordForbiddenMaterial.RAW_VERIFICATION_KEY,
    RecoveryVerifierRecordForbiddenMaterial.RAW_HMAC_MESSAGE,
    RecoveryVerifierRecordForbiddenMaterial.REPORT_TEXT,
    RecoveryVerifierRecordForbiddenMaterial.ATTACHMENT_CONTENT,
    RecoveryVerifierRecordForbiddenMaterial.RESPONSE_DEK,
    RecoveryVerifierRecordForbiddenMaterial.REPORT_DEK,
    RecoveryVerifierRecordForbiddenMaterial.OPERATOR_IDENTITY,
    RecoveryVerifierRecordForbiddenMaterial.AUDIT_HISTORY_MUTATION_CAPABILITY,
)


@dataclass(frozen=True, slots=True)
class RecoveryVerifierRecordFieldProfileV1:
    fields: tuple[RecoveryVerifierRecordField, ...]
    verifier_tag_size_bytes: int


@dataclass(frozen=True, slots=True)
class RecoveryVerifierRecordRequirementProfileV1:
    requirements: tuple[RecoveryVerifierRecordRequirement, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierRecordForbiddenMaterialProfileV1:
    forbidden_materials: tuple[RecoveryVerifierRecordForbiddenMaterial, ...]


@dataclass(frozen=True, slots=True)
class RecoveryVerifierRecordProfileV1:
    scheme_version: int
    fields: RecoveryVerifierRecordFieldProfileV1
    requirements: RecoveryVerifierRecordRequirementProfileV1
    forbidden_materials: RecoveryVerifierRecordForbiddenMaterialProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidRecoveryVerifierRecordProfileV1:
    profile: RecoveryVerifierRecordProfileV1

    @property
    def stores_secret(self) -> bool:
        return False

    @property
    def stores_raw_verifier_key(self) -> bool:
        return False

    @property
    def stores_raw_hmac_message(self) -> bool:
        return False

    @property
    def stores_response_dek(self) -> bool:
        return False

    @property
    def computes_verifier(self) -> bool:
        return False

    @property
    def tests_candidate_secret(self) -> bool:
        return False

    @property
    def performs_lookup(self) -> bool:
        return False

    @property
    def writes_database(self) -> bool:
        return False

    @property
    def exposes_endpoint(self) -> bool:
        return False

    @property
    def authorizes_recovery(self) -> bool:
        return False


def _reject() -> Never:
    raise RecoveryVerifierRecordDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_field(value: object) -> RecoveryVerifierRecordField:
    if isinstance(value, RecoveryVerifierRecordField):
        return value
    _reject()


def _require_requirement(value: object) -> RecoveryVerifierRecordRequirement:
    if isinstance(value, RecoveryVerifierRecordRequirement):
        return value
    _reject()


def _require_forbidden_material(
    value: object,
) -> RecoveryVerifierRecordForbiddenMaterial:
    if isinstance(value, RecoveryVerifierRecordForbiddenMaterial):
        return value
    _reject()


def _require_fields(
    value: object,
) -> tuple[RecoveryVerifierRecordField, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_field(item) for item in value)
    if normalized != RECOVERY_VERIFIER_RECORD_FIELDS_V1:
        _reject()
    return normalized


def _require_requirements(
    value: object,
) -> tuple[RecoveryVerifierRecordRequirement, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_requirement(item) for item in value)
    if normalized != RECOVERY_VERIFIER_RECORD_REQUIREMENTS_V1:
        _reject()
    return normalized


def _require_forbidden_materials(
    value: object,
) -> tuple[RecoveryVerifierRecordForbiddenMaterial, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_forbidden_material(item) for item in value)
    if normalized != RECOVERY_VERIFIER_RECORD_FORBIDDEN_MATERIALS_V1:
        _reject()
    return normalized


def validate_recovery_verifier_record_field_profile_v1(
    profile: RecoveryVerifierRecordFieldProfileV1,
) -> RecoveryVerifierRecordFieldProfileV1:
    if type(profile) is not RecoveryVerifierRecordFieldProfileV1:
        _reject()
    normalized = RecoveryVerifierRecordFieldProfileV1(
        fields=_require_fields(profile.fields),
        verifier_tag_size_bytes=_require_uint_exact(
            profile.verifier_tag_size_bytes,
            expected=RECOVERY_VERIFIER_RECORD_TAG_BYTES,
        ),
    )
    if normalized != expected_recovery_verifier_record_field_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_record_requirement_profile_v1(
    profile: RecoveryVerifierRecordRequirementProfileV1,
) -> RecoveryVerifierRecordRequirementProfileV1:
    if type(profile) is not RecoveryVerifierRecordRequirementProfileV1:
        _reject()
    normalized = RecoveryVerifierRecordRequirementProfileV1(
        requirements=_require_requirements(profile.requirements)
    )
    if normalized != expected_recovery_verifier_record_requirement_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_record_forbidden_material_profile_v1(
    profile: RecoveryVerifierRecordForbiddenMaterialProfileV1,
) -> RecoveryVerifierRecordForbiddenMaterialProfileV1:
    if type(profile) is not RecoveryVerifierRecordForbiddenMaterialProfileV1:
        _reject()
    normalized = RecoveryVerifierRecordForbiddenMaterialProfileV1(
        forbidden_materials=_require_forbidden_materials(
            profile.forbidden_materials
        )
    )
    if normalized != expected_recovery_verifier_record_forbidden_material_profile_v1():
        _reject()
    return normalized


def validate_recovery_verifier_record_profile_v1(
    profile: RecoveryVerifierRecordProfileV1,
) -> StructurallyValidRecoveryVerifierRecordProfileV1:
    if type(profile) is not RecoveryVerifierRecordProfileV1:
        _reject()
    normalized = RecoveryVerifierRecordProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=RECOVERY_VERIFIER_RECORD_PROFILE_VERSION,
        ),
        fields=validate_recovery_verifier_record_field_profile_v1(
            profile.fields
        ),
        requirements=validate_recovery_verifier_record_requirement_profile_v1(
            profile.requirements
        ),
        forbidden_materials=(
            validate_recovery_verifier_record_forbidden_material_profile_v1(
                profile.forbidden_materials
            )
        ),
    )
    if normalized != expected_recovery_verifier_record_profile_v1():
        _reject()
    return StructurallyValidRecoveryVerifierRecordProfileV1(normalized)


def expected_recovery_verifier_record_field_profile_v1(
) -> RecoveryVerifierRecordFieldProfileV1:
    return RecoveryVerifierRecordFieldProfileV1(
        fields=RECOVERY_VERIFIER_RECORD_FIELDS_V1,
        verifier_tag_size_bytes=RECOVERY_VERIFIER_RECORD_TAG_BYTES,
    )


def expected_recovery_verifier_record_requirement_profile_v1(
) -> RecoveryVerifierRecordRequirementProfileV1:
    return RecoveryVerifierRecordRequirementProfileV1(
        requirements=RECOVERY_VERIFIER_RECORD_REQUIREMENTS_V1
    )


def expected_recovery_verifier_record_forbidden_material_profile_v1(
) -> RecoveryVerifierRecordForbiddenMaterialProfileV1:
    return RecoveryVerifierRecordForbiddenMaterialProfileV1(
        forbidden_materials=RECOVERY_VERIFIER_RECORD_FORBIDDEN_MATERIALS_V1
    )


def expected_recovery_verifier_record_profile_v1(
) -> RecoveryVerifierRecordProfileV1:
    return RecoveryVerifierRecordProfileV1(
        scheme_version=RECOVERY_VERIFIER_RECORD_PROFILE_VERSION,
        fields=expected_recovery_verifier_record_field_profile_v1(),
        requirements=expected_recovery_verifier_record_requirement_profile_v1(),
        forbidden_materials=(
            expected_recovery_verifier_record_forbidden_material_profile_v1()
        ),
    )
