"""Negative tests for inert original-report text v1 descriptors."""

from dataclasses import FrozenInstanceError, fields, replace

from django.test import SimpleTestCase

from security_interfaces import (
    REPORT_TEXT_ACCEPTED_ORIGINAL_KIND,
    REPORT_TEXT_ENCODING,
    REPORT_TEXT_FORBIDDEN_CODEPOINTS,
    REPORT_TEXT_LINE_ENDING_PROFILE,
    REPORT_TEXT_MAX_SCALAR_VALUES,
    REPORT_TEXT_MAX_UTF8_BYTES,
    REPORT_TEXT_PROFILE_VERSION,
    REPORT_TEXT_UNICODE_NORMALIZATION,
    ReportTextAcceptedOriginalKind,
    ReportTextCanonicalizationProfileV1,
    ReportTextCharacterProfileV1,
    ReportTextDescriptorRejected,
    ReportTextEncoding,
    ReportTextLimitProfileV1,
    ReportTextLineEnding,
    ReportTextNormalization,
    validate_report_text_candidate_v1,
    validate_report_text_canonicalization_profile_v1,
    validate_report_text_character_profile_v1,
    validate_report_text_limit_profile_v1,
    validate_report_text_profile_v1,
)


def canonicalization_profile() -> ReportTextCanonicalizationProfileV1:
    return ReportTextCanonicalizationProfileV1(
        scheme_version=REPORT_TEXT_PROFILE_VERSION,
        normalization=ReportTextNormalization.NFC,
        line_ending=ReportTextLineEnding.LF,
        encoding=ReportTextEncoding.UTF8,
        accepted_original_kind=(
            ReportTextAcceptedOriginalKind.CANONICAL_UTF8_REPORT_TEXT
        ),
    )


def limit_profile() -> ReportTextLimitProfileV1:
    return ReportTextLimitProfileV1(
        max_scalar_values=REPORT_TEXT_MAX_SCALAR_VALUES,
        max_utf8_bytes=REPORT_TEXT_MAX_UTF8_BYTES,
    )


def character_profile() -> ReportTextCharacterProfileV1:
    return ReportTextCharacterProfileV1(
        forbidden_codepoints=REPORT_TEXT_FORBIDDEN_CODEPOINTS,
        rejects_unpaired_surrogates=True,
    )


class ReportTextRegistryTests(SimpleTestCase):
    def test_constants_and_registries_are_exact(self) -> None:
        self.assertEqual(REPORT_TEXT_PROFILE_VERSION, 1)
        self.assertEqual(REPORT_TEXT_MAX_SCALAR_VALUES, 5_000)
        self.assertEqual(REPORT_TEXT_MAX_UTF8_BYTES, 20_000)
        self.assertEqual(REPORT_TEXT_UNICODE_NORMALIZATION, "NFC")
        self.assertEqual(REPORT_TEXT_LINE_ENDING_PROFILE, "LF")
        self.assertEqual(REPORT_TEXT_ENCODING, "UTF-8")
        self.assertEqual(
            REPORT_TEXT_ACCEPTED_ORIGINAL_KIND,
            "CANONICAL_UTF8_REPORT_TEXT",
        )
        self.assertEqual(REPORT_TEXT_FORBIDDEN_CODEPOINTS, frozenset({0}))
        self.assertEqual(
            {item.value for item in ReportTextNormalization},
            {"NFC"},
        )
        self.assertEqual({item.value for item in ReportTextLineEnding}, {"LF"})
        self.assertEqual({item.value for item in ReportTextEncoding}, {"UTF-8"})
        self.assertEqual(
            {item.value for item in ReportTextAcceptedOriginalKind},
            {"CANONICAL_UTF8_REPORT_TEXT"},
        )

    def test_valid_candidate_returns_only_content_free_profile(self) -> None:
        candidate = "Linea uno\r\nCafe\u0301\rLinea tre"
        profile = validate_report_text_candidate_v1(candidate)
        self.assertNotIn(candidate, repr(profile))
        self.assertFalse(profile.retains_wire_report_text)
        self.assertFalse(profile.returns_canonical_bytes)
        self.assertFalse(profile.creates_plaintext_frame)
        self.assertFalse(profile.encrypts_report_text)
        self.assertFalse(profile.persists_report_text)
        self.assertFalse(profile.logs_report_text)
        self.assertFalse(profile.authorizes_submission)
        for field_name in (
            "text",
            "report_text",
            "wire_text",
            "normalized_text",
            "canonical_bytes",
            "plaintext_frame",
            "ciphertext",
            "submission_id",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(profile, field_name))


class ReportTextValidationTests(SimpleTestCase):
    def test_candidate_rejects_prohibited_content_without_echo(self) -> None:
        rejected = (
            object(),
            "contains\x00nul",
            "surrogate\ud800value",
        )
        for candidate in rejected:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(ReportTextDescriptorRejected) as raised:
                    validate_report_text_candidate_v1(candidate)
                self.assertEqual(
                    str(raised.exception),
                    "report_text_descriptor_rejected",
                )
                self.assertNotIn("surrogate", repr(raised.exception))

    def test_candidate_allows_plain_report_content_markers(self) -> None:
        profile = validate_report_text_candidate_v1(
            "Link-like text https://example.invalid and <angle brackets>"
        )
        self.assertFalse(profile.authorizes_submission)

    def test_candidate_rejects_scalar_and_utf8_byte_limits(self) -> None:
        with self.assertRaises(ReportTextDescriptorRejected):
            validate_report_text_candidate_v1(
                "a" * (REPORT_TEXT_MAX_SCALAR_VALUES + 1)
            )
        with self.assertRaises(ReportTextDescriptorRejected):
            validate_report_text_candidate_v1(
                "\U0001f642" * (REPORT_TEXT_MAX_SCALAR_VALUES + 1)
            )
        self.assertIsNotNone(validate_report_text_candidate_v1(""))
        self.assertIsNotNone(
            validate_report_text_candidate_v1(
                "\U0001f642" * REPORT_TEXT_MAX_SCALAR_VALUES
            )
        )

    def test_profile_validators_reject_wrong_profiles(self) -> None:
        canonicalization = canonicalization_profile()
        limits = limit_profile()
        characters = character_profile()
        self.assertEqual(
            validate_report_text_canonicalization_profile_v1(
                canonicalization
            ),
            canonicalization,
        )
        self.assertEqual(validate_report_text_limit_profile_v1(limits), limits)
        self.assertEqual(
            validate_report_text_character_profile_v1(characters),
            characters,
        )

        for candidate in (
            object(),
            replace(canonicalization, scheme_version=2),
            replace(canonicalization, normalization="NFD"),
            replace(canonicalization, line_ending="CRLF"),
            replace(canonicalization, encoding="UTF-16"),
            replace(canonicalization, accepted_original_kind="WIRE_TEXT"),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportTextDescriptorRejected):
                    validate_report_text_canonicalization_profile_v1(candidate)

        for candidate in (
            object(),
            replace(limits, max_scalar_values=5_001),
            replace(limits, max_utf8_bytes=20_001),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportTextDescriptorRejected):
                    validate_report_text_limit_profile_v1(candidate)

        for candidate in (
            object(),
            replace(characters, forbidden_codepoints=frozenset()),
            replace(characters, rejects_unpaired_surrogates=False),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ReportTextDescriptorRejected):
                    validate_report_text_character_profile_v1(candidate)

    def test_complete_profile_is_immutable_and_non_authorizing(self) -> None:
        profile = validate_report_text_profile_v1(
            canonicalization_profile=canonicalization_profile(),
            limit_profile=limit_profile(),
            character_profile=character_profile(),
        )
        self.assertEqual(
            {field.name for field in fields(type(profile))},
            {
                "canonicalization_profile",
                "limit_profile",
                "character_profile",
            },
        )
        self.assertFalse(profile.retains_wire_report_text)
        self.assertFalse(profile.authorizes_submission)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            profile.authorizes_submission = True

    def test_controlled_error_never_echoes_report_text(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        with self.assertRaises(ReportTextDescriptorRejected) as raised:
            validate_report_text_candidate_v1(f"{sentinel}\x00")
        self.assertEqual(str(raised.exception), "report_text_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
