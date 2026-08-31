"""Negative tests for inert Response Note text v1 descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    RESPONSE_TEXT_CONTENT_KIND,
    RESPONSE_TEXT_ENCODING,
    RESPONSE_TEXT_FORBIDDEN_CHARACTERS,
    RESPONSE_TEXT_FORBIDDEN_CODEPOINTS,
    RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS,
    RESPONSE_TEXT_LINE_ENDING_PROFILE,
    RESPONSE_TEXT_MAX_SCALAR_VALUES,
    RESPONSE_TEXT_MAX_UTF8_BYTES,
    RESPONSE_TEXT_PROFILE_VERSION,
    RESPONSE_TEXT_UNICODE_NORMALIZATION,
    ResponseTextCanonicalizationProfileV1,
    ResponseTextContentKind,
    ResponseTextContentRestrictionProfileV1,
    ResponseTextDescriptorRejected,
    ResponseTextEncoding,
    ResponseTextLimitProfileV1,
    ResponseTextLineEnding,
    ResponseTextNormalization,
    validate_response_text_candidate_v1,
    validate_response_text_canonicalization_profile_v1,
    validate_response_text_content_restriction_profile_v1,
    validate_response_text_limit_profile_v1,
    validate_response_text_profile_v1,
)


def canonicalization_profile() -> ResponseTextCanonicalizationProfileV1:
    return ResponseTextCanonicalizationProfileV1(
        scheme_version=RESPONSE_TEXT_PROFILE_VERSION,
        normalization=ResponseTextNormalization.NFC,
        line_ending=ResponseTextLineEnding.LF,
        encoding=ResponseTextEncoding.UTF8,
    )


def limit_profile() -> ResponseTextLimitProfileV1:
    return ResponseTextLimitProfileV1(
        max_scalar_values=RESPONSE_TEXT_MAX_SCALAR_VALUES,
        max_utf8_bytes=RESPONSE_TEXT_MAX_UTF8_BYTES,
    )


def restriction_profile() -> ResponseTextContentRestrictionProfileV1:
    return ResponseTextContentRestrictionProfileV1(
        content_kind=ResponseTextContentKind.PLAIN_TEXT,
        forbidden_codepoints=RESPONSE_TEXT_FORBIDDEN_CODEPOINTS,
        forbidden_characters=RESPONSE_TEXT_FORBIDDEN_CHARACTERS,
        forbidden_link_markers=RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS,
    )


class ResponseTextRegistryTests(SimpleTestCase):
    def test_constants_and_registries_are_exact(self) -> None:
        self.assertEqual(RESPONSE_TEXT_PROFILE_VERSION, 1)
        self.assertEqual(RESPONSE_TEXT_MAX_SCALAR_VALUES, 5_000)
        self.assertEqual(RESPONSE_TEXT_MAX_UTF8_BYTES, 20_000)
        self.assertEqual(RESPONSE_TEXT_UNICODE_NORMALIZATION, "NFC")
        self.assertEqual(RESPONSE_TEXT_LINE_ENDING_PROFILE, "LF")
        self.assertEqual(RESPONSE_TEXT_ENCODING, "UTF-8")
        self.assertEqual(RESPONSE_TEXT_CONTENT_KIND, "PLAIN_TEXT")
        self.assertEqual(RESPONSE_TEXT_FORBIDDEN_CODEPOINTS, frozenset({0}))
        self.assertEqual(RESPONSE_TEXT_FORBIDDEN_CHARACTERS, frozenset({"<", ">"}))
        self.assertEqual(
            RESPONSE_TEXT_FORBIDDEN_LINK_MARKERS,
            ("http://", "https://", "mailto:", "tel:", "ftp://", "www."),
        )
        self.assertEqual(
            {item.value for item in ResponseTextNormalization},
            {"NFC"},
        )
        self.assertEqual({item.value for item in ResponseTextLineEnding}, {"LF"})
        self.assertEqual({item.value for item in ResponseTextEncoding}, {"UTF-8"})
        self.assertEqual(
            {item.value for item in ResponseTextContentKind},
            {"PLAIN_TEXT"},
        )

    def test_valid_candidate_returns_only_content_free_profile(self) -> None:
        candidate = "Linea uno\r\nCafe\u0301\rLinea tre"
        profile = validate_response_text_candidate_v1(candidate)
        self.assertNotIn(candidate, repr(profile))
        self.assertFalse(profile.retains_response_text)
        self.assertFalse(profile.creates_server_side_draft)
        self.assertFalse(profile.produces_canonical_bytes)
        self.assertFalse(profile.computes_artifact_digest)
        self.assertFalse(profile.authorizes_finalization)
        for field_name in (
            "text",
            "response_note",
            "normalized_text",
            "canonical_bytes",
            "artifact_digest",
            "draft_id",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(profile, field_name))


class ResponseTextValidationTests(SimpleTestCase):
    def test_candidate_rejects_prohibited_content_without_echo(self) -> None:
        rejected = (
            object(),
            "contains\x00nul",
            "surrogate\ud800value",
            "<strong>html</strong>",
            "Visit https://example.invalid",
            "Visit HTTP://example.invalid",
            "mail me at mailto:person@example.invalid",
            "phone tel:+390000000000",
            "ftp://example.invalid/file",
            "www.example.invalid",
        )
        for candidate in rejected:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(ResponseTextDescriptorRejected) as raised:
                    validate_response_text_candidate_v1(candidate)
                self.assertEqual(
                    str(raised.exception),
                    "response_text_descriptor_rejected",
                )
                self.assertNotIn("example.invalid", repr(raised.exception))

    def test_candidate_rejects_scalar_and_utf8_byte_limits(self) -> None:
        with self.assertRaises(ResponseTextDescriptorRejected):
            validate_response_text_candidate_v1(
                "a" * (RESPONSE_TEXT_MAX_SCALAR_VALUES + 1)
            )
        with self.assertRaises(ResponseTextDescriptorRejected):
            validate_response_text_candidate_v1(
                "\U0001f642" * (RESPONSE_TEXT_MAX_SCALAR_VALUES + 1)
            )
        self.assertIsNotNone(validate_response_text_candidate_v1(""))
        self.assertIsNotNone(
            validate_response_text_candidate_v1(
                "\U0001f642" * RESPONSE_TEXT_MAX_SCALAR_VALUES
            )
        )

    def test_profile_validators_reject_wrong_profiles(self) -> None:
        canonicalization = canonicalization_profile()
        limits = limit_profile()
        restrictions = restriction_profile()
        self.assertEqual(
            validate_response_text_canonicalization_profile_v1(
                canonicalization
            ),
            canonicalization,
        )
        self.assertEqual(validate_response_text_limit_profile_v1(limits), limits)
        self.assertEqual(
            validate_response_text_content_restriction_profile_v1(restrictions),
            restrictions,
        )

        for candidate in (
            object(),
            replace(canonicalization, scheme_version=2),
            replace(canonicalization, normalization="NFD"),
            replace(canonicalization, line_ending="CRLF"),
            replace(canonicalization, encoding="UTF-16"),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseTextDescriptorRejected):
                    validate_response_text_canonicalization_profile_v1(candidate)

        for candidate in (
            object(),
            replace(limits, max_scalar_values=5_001),
            replace(limits, max_utf8_bytes=20_001),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseTextDescriptorRejected):
                    validate_response_text_limit_profile_v1(candidate)

        for candidate in (
            object(),
            replace(restrictions, content_kind="HTML"),
            replace(restrictions, forbidden_codepoints=frozenset()),
            replace(restrictions, forbidden_characters=frozenset()),
            replace(restrictions, forbidden_link_markers=("https://",)),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ResponseTextDescriptorRejected):
                    validate_response_text_content_restriction_profile_v1(
                        candidate
                    )

    def test_complete_profile_is_immutable_and_non_authorizing(self) -> None:
        profile = validate_response_text_profile_v1(
            canonicalization_profile=canonicalization_profile(),
            limit_profile=limit_profile(),
            content_restriction_profile=restriction_profile(),
        )
        self.assertEqual(
            {field.name for field in fields(type(profile))},
            {
                "canonicalization_profile",
                "limit_profile",
                "content_restriction_profile",
            },
        )
        self.assertFalse(profile.retains_response_text)
        self.assertFalse(profile.authorizes_finalization)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            profile.authorizes_finalization = True

    def test_controlled_error_never_echoes_response_text(self) -> None:
        sentinel = "RESPONSE_TEXT_SENTINEL"
        with self.assertRaises(ResponseTextDescriptorRejected) as raised:
            validate_response_text_candidate_v1(f"<{sentinel}>")
        self.assertEqual(str(raised.exception), "response_text_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
