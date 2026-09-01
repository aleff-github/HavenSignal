"""Inert operator safe-view descriptors for attachment PNG representations.

This module validates only static safe-view metadata. It does not decrypt
attachments, render files, validate PNG bytes, call a sandbox, persist output,
serve responses, inspect leases, or authorize operator access.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import SafeViewDescriptorRejected


SAFE_VIEW_PROTOCOL_VERSION = 1
SAFE_VIEW_RENDER_DPI = 144
SAFE_VIEW_OUTPUT_DIMENSION_MAX_PIXELS = 4_096
SAFE_VIEW_OUTPUT_MAX_BYTES = 16_777_216
SAFE_VIEW_TOTAL_RENDERED_PIXELS_MAX = 50_000_000
SAFE_VIEW_TOTAL_OUTPUT_MAX_BYTES = 134_217_728
SAFE_VIEW_CONTENT_TYPE = "image/png"
SAFE_VIEW_CACHE_CONTROL = "no-store"
SAFE_VIEW_X_CONTENT_TYPE_OPTIONS = "nosniff"


class SafeViewOutputFormat(StrEnum):
    PNG = "PNG"


class SafeViewColorProfile(StrEnum):
    SRGB_8_BIT = "SRGB_8_BIT"


class SafeViewRequestInitiation(StrEnum):
    POST_INITIATED = "POST_INITIATED"


class SafeViewBinding(StrEnum):
    AUTHENTICATED_OPERATOR = "AUTHENTICATED_OPERATOR"
    REPORT_STATE_VERSION = "REPORT_STATE_VERSION"
    LEASE_GENERATION = "LEASE_GENERATION"
    OBJECT_IDENTIFIER = "OBJECT_IDENTIFIER"


SAFE_VIEW_OUTPUT_FORMATS_V1 = (SafeViewOutputFormat.PNG,)
SAFE_VIEW_COLOR_PROFILES_V1 = (SafeViewColorProfile.SRGB_8_BIT,)
SAFE_VIEW_REQUIRED_BINDINGS_V1 = (
    SafeViewBinding.AUTHENTICATED_OPERATOR,
    SafeViewBinding.REPORT_STATE_VERSION,
    SafeViewBinding.LEASE_GENERATION,
    SafeViewBinding.OBJECT_IDENTIFIER,
)


@dataclass(frozen=True, slots=True)
class SafeViewOutputLimitProfileV1:
    output_dimension_max_pixels: int
    output_max_bytes: int
    total_rendered_pixels_max: int
    total_output_max_bytes: int


@dataclass(frozen=True, slots=True)
class SafeViewRepresentationProfileV1:
    output_formats: tuple[SafeViewOutputFormat, ...]
    color_profiles: tuple[SafeViewColorProfile, ...]
    render_dpi: int
    strips_metadata: bool
    strips_original_filename: bool
    strips_links_text_forms_and_scripts: bool


@dataclass(frozen=True, slots=True)
class SafeViewResponseHeaderProfileV1:
    content_type: str
    cache_control: str
    x_content_type_options: str
    range_requests_allowed: bool
    public_url_allowed: bool
    alternate_content_negotiation_allowed: bool


@dataclass(frozen=True, slots=True)
class SafeViewAuthorizationBoundaryProfileV1:
    request_initiation: SafeViewRequestInitiation
    required_bindings: tuple[SafeViewBinding, ...]
    ordinary_original_download_allowed: bool
    safe_view_is_durable_report_object: bool
    safe_view_is_browser_persistent: bool
    safe_view_is_audit_payload: bool


@dataclass(frozen=True, slots=True)
class SafeViewProtocolProfileV1:
    scheme_version: int
    output_limits: SafeViewOutputLimitProfileV1
    representation_profile: SafeViewRepresentationProfileV1
    response_headers: SafeViewResponseHeaderProfileV1
    authorization_boundary: SafeViewAuthorizationBoundaryProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidSafeViewProfileV1:
    profile: SafeViewProtocolProfileV1

    @property
    def decrypts_attachment(self) -> bool:
        return False

    @property
    def renders_attachment(self) -> bool:
        return False

    @property
    def validates_png_bytes(self) -> bool:
        return False

    @property
    def calls_sandbox(self) -> bool:
        return False

    @property
    def persists_safe_output(self) -> bool:
        return False

    @property
    def serves_response(self) -> bool:
        return False

    @property
    def authorizes_operator_access(self) -> bool:
        return False


def _reject() -> Never:
    raise SafeViewDescriptorRejected()


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


def _require_output_format(value: object) -> SafeViewOutputFormat:
    if isinstance(value, SafeViewOutputFormat):
        return value
    if type(value) is str:
        for output_format in SafeViewOutputFormat:
            if value == output_format.value:
                return output_format
    _reject()


def _require_color_profile(value: object) -> SafeViewColorProfile:
    if isinstance(value, SafeViewColorProfile):
        return value
    if type(value) is str:
        for color_profile in SafeViewColorProfile:
            if value == color_profile.value:
                return color_profile
    _reject()


def _require_request_initiation(
    value: object,
) -> SafeViewRequestInitiation:
    if isinstance(value, SafeViewRequestInitiation):
        return value
    if type(value) is str:
        for initiation in SafeViewRequestInitiation:
            if value == initiation.value:
                return initiation
    _reject()


def _require_binding(value: object) -> SafeViewBinding:
    if isinstance(value, SafeViewBinding):
        return value
    if type(value) is str:
        for binding in SafeViewBinding:
            if value == binding.value:
                return binding
    _reject()


def _require_output_formats(
    value: object,
) -> tuple[SafeViewOutputFormat, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_output_format(output_format) for output_format in value
    )
    if normalized != SAFE_VIEW_OUTPUT_FORMATS_V1:
        _reject()
    return normalized


def _require_color_profiles(
    value: object,
) -> tuple[SafeViewColorProfile, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_color_profile(color_profile) for color_profile in value
    )
    if normalized != SAFE_VIEW_COLOR_PROFILES_V1:
        _reject()
    return normalized


def _require_bindings(value: object) -> tuple[SafeViewBinding, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_binding(binding) for binding in value)
    if normalized != SAFE_VIEW_REQUIRED_BINDINGS_V1:
        _reject()
    return normalized


def validate_safe_view_output_limit_profile_v1(
    profile: SafeViewOutputLimitProfileV1,
) -> SafeViewOutputLimitProfileV1:
    if type(profile) is not SafeViewOutputLimitProfileV1:
        _reject()
    return SafeViewOutputLimitProfileV1(
        output_dimension_max_pixels=_require_uint_exact(
            profile.output_dimension_max_pixels,
            expected=SAFE_VIEW_OUTPUT_DIMENSION_MAX_PIXELS,
        ),
        output_max_bytes=_require_uint_exact(
            profile.output_max_bytes,
            expected=SAFE_VIEW_OUTPUT_MAX_BYTES,
        ),
        total_rendered_pixels_max=_require_uint_exact(
            profile.total_rendered_pixels_max,
            expected=SAFE_VIEW_TOTAL_RENDERED_PIXELS_MAX,
        ),
        total_output_max_bytes=_require_uint_exact(
            profile.total_output_max_bytes,
            expected=SAFE_VIEW_TOTAL_OUTPUT_MAX_BYTES,
        ),
    )


def validate_safe_view_representation_profile_v1(
    profile: SafeViewRepresentationProfileV1,
) -> SafeViewRepresentationProfileV1:
    if type(profile) is not SafeViewRepresentationProfileV1:
        _reject()
    return SafeViewRepresentationProfileV1(
        output_formats=_require_output_formats(profile.output_formats),
        color_profiles=_require_color_profiles(profile.color_profiles),
        render_dpi=_require_uint_exact(
            profile.render_dpi,
            expected=SAFE_VIEW_RENDER_DPI,
        ),
        strips_metadata=_require_bool_exact(
            profile.strips_metadata,
            expected=True,
        ),
        strips_original_filename=_require_bool_exact(
            profile.strips_original_filename,
            expected=True,
        ),
        strips_links_text_forms_and_scripts=_require_bool_exact(
            profile.strips_links_text_forms_and_scripts,
            expected=True,
        ),
    )


def validate_safe_view_response_header_profile_v1(
    profile: SafeViewResponseHeaderProfileV1,
) -> SafeViewResponseHeaderProfileV1:
    if type(profile) is not SafeViewResponseHeaderProfileV1:
        _reject()
    return SafeViewResponseHeaderProfileV1(
        content_type=_require_string_exact(
            profile.content_type,
            expected=SAFE_VIEW_CONTENT_TYPE,
        ),
        cache_control=_require_string_exact(
            profile.cache_control,
            expected=SAFE_VIEW_CACHE_CONTROL,
        ),
        x_content_type_options=_require_string_exact(
            profile.x_content_type_options,
            expected=SAFE_VIEW_X_CONTENT_TYPE_OPTIONS,
        ),
        range_requests_allowed=_require_bool_exact(
            profile.range_requests_allowed,
            expected=False,
        ),
        public_url_allowed=_require_bool_exact(
            profile.public_url_allowed,
            expected=False,
        ),
        alternate_content_negotiation_allowed=_require_bool_exact(
            profile.alternate_content_negotiation_allowed,
            expected=False,
        ),
    )


def validate_safe_view_authorization_boundary_profile_v1(
    profile: SafeViewAuthorizationBoundaryProfileV1,
) -> SafeViewAuthorizationBoundaryProfileV1:
    if type(profile) is not SafeViewAuthorizationBoundaryProfileV1:
        _reject()
    return SafeViewAuthorizationBoundaryProfileV1(
        request_initiation=_require_request_initiation(
            profile.request_initiation
        ),
        required_bindings=_require_bindings(profile.required_bindings),
        ordinary_original_download_allowed=_require_bool_exact(
            profile.ordinary_original_download_allowed,
            expected=False,
        ),
        safe_view_is_durable_report_object=_require_bool_exact(
            profile.safe_view_is_durable_report_object,
            expected=False,
        ),
        safe_view_is_browser_persistent=_require_bool_exact(
            profile.safe_view_is_browser_persistent,
            expected=False,
        ),
        safe_view_is_audit_payload=_require_bool_exact(
            profile.safe_view_is_audit_payload,
            expected=False,
        ),
    )


def validate_safe_view_protocol_profile_v1(
    profile: SafeViewProtocolProfileV1,
) -> StructurallyValidSafeViewProfileV1:
    if type(profile) is not SafeViewProtocolProfileV1:
        _reject()
    normalized = SafeViewProtocolProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=SAFE_VIEW_PROTOCOL_VERSION,
        ),
        output_limits=validate_safe_view_output_limit_profile_v1(
            profile.output_limits
        ),
        representation_profile=validate_safe_view_representation_profile_v1(
            profile.representation_profile
        ),
        response_headers=validate_safe_view_response_header_profile_v1(
            profile.response_headers
        ),
        authorization_boundary=(
            validate_safe_view_authorization_boundary_profile_v1(
                profile.authorization_boundary
            )
        ),
    )
    return StructurallyValidSafeViewProfileV1(profile=normalized)


def expected_safe_view_protocol_profile_v1() -> SafeViewProtocolProfileV1:
    """Return only the approved safe-view metadata."""

    return SafeViewProtocolProfileV1(
        scheme_version=SAFE_VIEW_PROTOCOL_VERSION,
        output_limits=SafeViewOutputLimitProfileV1(
            output_dimension_max_pixels=SAFE_VIEW_OUTPUT_DIMENSION_MAX_PIXELS,
            output_max_bytes=SAFE_VIEW_OUTPUT_MAX_BYTES,
            total_rendered_pixels_max=SAFE_VIEW_TOTAL_RENDERED_PIXELS_MAX,
            total_output_max_bytes=SAFE_VIEW_TOTAL_OUTPUT_MAX_BYTES,
        ),
        representation_profile=SafeViewRepresentationProfileV1(
            output_formats=SAFE_VIEW_OUTPUT_FORMATS_V1,
            color_profiles=SAFE_VIEW_COLOR_PROFILES_V1,
            render_dpi=SAFE_VIEW_RENDER_DPI,
            strips_metadata=True,
            strips_original_filename=True,
            strips_links_text_forms_and_scripts=True,
        ),
        response_headers=SafeViewResponseHeaderProfileV1(
            content_type=SAFE_VIEW_CONTENT_TYPE,
            cache_control=SAFE_VIEW_CACHE_CONTROL,
            x_content_type_options=SAFE_VIEW_X_CONTENT_TYPE_OPTIONS,
            range_requests_allowed=False,
            public_url_allowed=False,
            alternate_content_negotiation_allowed=False,
        ),
        authorization_boundary=SafeViewAuthorizationBoundaryProfileV1(
            request_initiation=SafeViewRequestInitiation.POST_INITIATED,
            required_bindings=SAFE_VIEW_REQUIRED_BINDINGS_V1,
            ordinary_original_download_allowed=False,
            safe_view_is_durable_report_object=False,
            safe_view_is_browser_persistent=False,
            safe_view_is_audit_payload=False,
        ),
    )
