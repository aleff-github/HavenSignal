"""Negative tests for inert attachment safe-view descriptors."""

from dataclasses import FrozenInstanceError, replace

from django.test import SimpleTestCase

from security_interfaces import (
    SAFE_VIEW_CACHE_CONTROL,
    SAFE_VIEW_COLOR_PROFILES_V1,
    SAFE_VIEW_CONTENT_TYPE,
    SAFE_VIEW_OUTPUT_DIMENSION_MAX_PIXELS,
    SAFE_VIEW_OUTPUT_FORMATS_V1,
    SAFE_VIEW_OUTPUT_MAX_BYTES,
    SAFE_VIEW_PROTOCOL_VERSION,
    SAFE_VIEW_RENDER_DPI,
    SAFE_VIEW_REQUIRED_BINDINGS_V1,
    SAFE_VIEW_TOTAL_OUTPUT_MAX_BYTES,
    SAFE_VIEW_TOTAL_RENDERED_PIXELS_MAX,
    SAFE_VIEW_X_CONTENT_TYPE_OPTIONS,
    SafeViewBinding,
    SafeViewColorProfile,
    SafeViewDescriptorRejected,
    SafeViewOutputFormat,
    SafeViewOutputLimitProfileV1,
    SafeViewRepresentationProfileV1,
    SafeViewRequestInitiation,
    SafeViewResponseHeaderProfileV1,
    expected_safe_view_protocol_profile_v1,
    validate_safe_view_protocol_profile_v1,
)


class SafeViewProfileTests(SimpleTestCase):
    def test_constants_match_approved_safe_view_profile(self) -> None:
        self.assertEqual(SAFE_VIEW_PROTOCOL_VERSION, 1)
        self.assertEqual(SAFE_VIEW_RENDER_DPI, 144)
        self.assertEqual(SAFE_VIEW_OUTPUT_DIMENSION_MAX_PIXELS, 4_096)
        self.assertEqual(SAFE_VIEW_OUTPUT_MAX_BYTES, 16_777_216)
        self.assertEqual(SAFE_VIEW_TOTAL_RENDERED_PIXELS_MAX, 50_000_000)
        self.assertEqual(SAFE_VIEW_TOTAL_OUTPUT_MAX_BYTES, 134_217_728)
        self.assertEqual(SAFE_VIEW_CONTENT_TYPE, "image/png")
        self.assertEqual(SAFE_VIEW_CACHE_CONTROL, "no-store")
        self.assertEqual(SAFE_VIEW_X_CONTENT_TYPE_OPTIONS, "nosniff")
        self.assertEqual(SAFE_VIEW_OUTPUT_FORMATS_V1, (SafeViewOutputFormat.PNG,))
        self.assertEqual(
            SAFE_VIEW_COLOR_PROFILES_V1,
            (SafeViewColorProfile.SRGB_8_BIT,),
        )
        self.assertEqual(
            SAFE_VIEW_REQUIRED_BINDINGS_V1,
            (
                SafeViewBinding.AUTHENTICATED_OPERATOR,
                SafeViewBinding.REPORT_STATE_VERSION,
                SafeViewBinding.LEASE_GENERATION,
                SafeViewBinding.OBJECT_IDENTIFIER,
            ),
        )

    def test_validated_profile_is_inert_and_non_authorizing(self) -> None:
        validated = validate_safe_view_protocol_profile_v1(
            expected_safe_view_protocol_profile_v1()
        )
        self.assertFalse(validated.decrypts_attachment)
        self.assertFalse(validated.renders_attachment)
        self.assertFalse(validated.validates_png_bytes)
        self.assertFalse(validated.calls_sandbox)
        self.assertFalse(validated.persists_safe_output)
        self.assertFalse(validated.serves_response)
        self.assertFalse(validated.authorizes_operator_access)
        self.assertTrue(
            validated.profile.representation_profile.strips_metadata
        )
        self.assertTrue(
            validated.profile.representation_profile.strips_original_filename
        )
        self.assertTrue(
            validated
            .profile
            .representation_profile
            .strips_links_text_forms_and_scripts
        )
        self.assertFalse(
            validated
            .profile
            .authorization_boundary
            .ordinary_original_download_allowed
        )
        self.assertFalse(
            validated
            .profile
            .authorization_boundary
            .safe_view_is_durable_report_object
        )
        self.assertFalse(
            validated.profile.authorization_boundary.safe_view_is_audit_payload
        )
        for field_name in (
            "original_bytes",
            "safe_png_bytes",
            "lease_id",
            "operator_id",
            "filename",
            "sandbox_handle",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class SafeViewValidationTests(SimpleTestCase):
    def test_profile_rejects_changed_limits_and_rendering_claims(self) -> None:
        valid = expected_safe_view_protocol_profile_v1()
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(
                valid,
                output_limits=SafeViewOutputLimitProfileV1(
                    output_dimension_max_pixels=(
                        SAFE_VIEW_OUTPUT_DIMENSION_MAX_PIXELS + 1
                    ),
                    output_max_bytes=SAFE_VIEW_OUTPUT_MAX_BYTES,
                    total_rendered_pixels_max=SAFE_VIEW_TOTAL_RENDERED_PIXELS_MAX,
                    total_output_max_bytes=SAFE_VIEW_TOTAL_OUTPUT_MAX_BYTES,
                ),
            ),
            replace(
                valid,
                representation_profile=SafeViewRepresentationProfileV1(
                    output_formats=SAFE_VIEW_OUTPUT_FORMATS_V1,
                    color_profiles=SAFE_VIEW_COLOR_PROFILES_V1,
                    render_dpi=SAFE_VIEW_RENDER_DPI,
                    strips_metadata=False,
                    strips_original_filename=True,
                    strips_links_text_forms_and_scripts=True,
                ),
            ),
            replace(
                valid,
                representation_profile=replace(
                    valid.representation_profile,
                    output_formats=("PDF",),
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SafeViewDescriptorRejected):
                    validate_safe_view_protocol_profile_v1(candidate)

    def test_profile_rejects_unsafe_headers_and_access_boundaries(self) -> None:
        valid = expected_safe_view_protocol_profile_v1()
        for candidate in (
            replace(
                valid,
                response_headers=SafeViewResponseHeaderProfileV1(
                    content_type="application/pdf",
                    cache_control=SAFE_VIEW_CACHE_CONTROL,
                    x_content_type_options=SAFE_VIEW_X_CONTENT_TYPE_OPTIONS,
                    range_requests_allowed=False,
                    public_url_allowed=False,
                    alternate_content_negotiation_allowed=False,
                ),
            ),
            replace(
                valid,
                response_headers=replace(
                    valid.response_headers,
                    range_requests_allowed=True,
                ),
            ),
            replace(
                valid,
                authorization_boundary=replace(
                    valid.authorization_boundary,
                    request_initiation=SafeViewRequestInitiation("POST_INITIATED"),
                    ordinary_original_download_allowed=True,
                ),
            ),
            replace(
                valid,
                authorization_boundary=replace(
                    valid.authorization_boundary,
                    required_bindings=tuple(reversed(SAFE_VIEW_REQUIRED_BINDINGS_V1)),
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SafeViewDescriptorRejected):
                    validate_safe_view_protocol_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        profile = expected_safe_view_protocol_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        validated = validate_safe_view_protocol_profile_v1(profile)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.serves_response = True

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "SAFE_VIEW_SENTINEL"
        valid = expected_safe_view_protocol_profile_v1()
        with self.assertRaises(SafeViewDescriptorRejected) as raised:
            validate_safe_view_protocol_profile_v1(
                replace(valid, response_headers=sentinel)
            )
        self.assertEqual(str(raised.exception), "safe_view_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
