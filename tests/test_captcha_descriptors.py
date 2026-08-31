"""Negative tests for inert no-JavaScript CAPTCHA descriptors."""

from dataclasses import FrozenInstanceError, replace

from django.test import SimpleTestCase

from security_interfaces import (
    CAPTCHA_ANSWER_ALPHABET,
    CAPTCHA_ANSWER_LENGTH,
    CAPTCHA_BUCKET_LIMITS_V1,
    CAPTCHA_CHALLENGE_STATES_V1,
    CAPTCHA_CLEANUP_AFTER_SECONDS,
    CAPTCHA_EXPIRY_SECONDS,
    CAPTCHA_FORM_SCOPE_RAW_BYTES,
    CAPTCHA_IDENTIFIER_ALPHABET,
    CAPTCHA_IDENTIFIER_ENCODED_LENGTH,
    CAPTCHA_IDENTIFIER_RAW_BYTES,
    CAPTCHA_PNG_HEIGHT_PIXELS,
    CAPTCHA_PNG_MAX_BYTES,
    CAPTCHA_PNG_WIDTH_PIXELS,
    CAPTCHA_PRODUCTION_GATES_V1,
    CAPTCHA_PROTOCOL_VERSION,
    CAPTCHA_PURPOSES_V1,
    CaptchaAbuseControlProfileV1,
    CaptchaAction,
    CaptchaAnswerShapeV1,
    CaptchaBucketLimitV1,
    CaptchaChallengeState,
    CaptchaDescriptorRejected,
    CaptchaProductionGate,
    CaptchaPurpose,
    expected_captcha_protocol_profile_v1,
    validate_captcha_answer_text_v1,
    validate_captcha_identifier_text_v1,
    validate_captcha_protocol_profile_v1,
)


class CaptchaDescriptorProfileTests(SimpleTestCase):
    def test_protocol_constants_match_the_approved_v1_profile(self) -> None:
        self.assertEqual(CAPTCHA_PROTOCOL_VERSION, 1)
        self.assertEqual(CAPTCHA_IDENTIFIER_RAW_BYTES, 16)
        self.assertEqual(CAPTCHA_IDENTIFIER_ENCODED_LENGTH, 22)
        self.assertEqual(CAPTCHA_FORM_SCOPE_RAW_BYTES, 16)
        self.assertEqual(CAPTCHA_ANSWER_LENGTH, 6)
        self.assertEqual(CAPTCHA_EXPIRY_SECONDS, 300)
        self.assertEqual(CAPTCHA_CLEANUP_AFTER_SECONDS, 900)
        self.assertEqual(CAPTCHA_PNG_WIDTH_PIXELS, 240)
        self.assertEqual(CAPTCHA_PNG_HEIGHT_PIXELS, 80)
        self.assertEqual(CAPTCHA_PNG_MAX_BYTES, 65_536)
        self.assertEqual(
            CAPTCHA_ANSWER_ALPHABET,
            frozenset("23456789ABCDEFGHJKLMNPQRSTUVWXYZ"),
        )
        self.assertNotIn("0", CAPTCHA_ANSWER_ALPHABET)
        self.assertNotIn("1", CAPTCHA_ANSWER_ALPHABET)
        self.assertNotIn("I", CAPTCHA_ANSWER_ALPHABET)
        self.assertNotIn("O", CAPTCHA_ANSWER_ALPHABET)
        self.assertEqual(
            CAPTCHA_PURPOSES_V1,
            (
                CaptchaPurpose.SUBMIT_REPORT,
                CaptchaPurpose.RECOVER_RESPONSE,
            ),
        )
        self.assertEqual(
            CAPTCHA_CHALLENGE_STATES_V1,
            (
                CaptchaChallengeState.READY,
                CaptchaChallengeState.CONSUMED,
                CaptchaChallengeState.EXPIRED,
            ),
        )
        self.assertEqual(
            CAPTCHA_PRODUCTION_GATES_V1,
            (
                CaptchaProductionGate.PINNED_PILLOW_AND_FONT_REVIEW,
                CaptchaProductionGate.SELF_HOSTED_AUDIO_ACCESSIBILITY_REVIEW,
                CaptchaProductionGate.POSTGRESQL_CONCURRENCY_REVIEW,
                CaptchaProductionGate.PRODUCTION_BOUNDARY_REVIEW,
            ),
        )

    def test_bucket_limits_are_global_purpose_specific_and_not_identity_based(
        self,
    ) -> None:
        self.assertEqual(
            CAPTCHA_BUCKET_LIMITS_V1,
            (
                CaptchaBucketLimitV1(
                    CaptchaPurpose.SUBMIT_REPORT,
                    CaptchaAction.ISSUE,
                    20,
                    1,
                    2,
                ),
                CaptchaBucketLimitV1(
                    CaptchaPurpose.SUBMIT_REPORT,
                    CaptchaAction.VERIFY,
                    20,
                    1,
                    3,
                ),
                CaptchaBucketLimitV1(
                    CaptchaPurpose.SUBMIT_REPORT,
                    CaptchaAction.FETCH_REPRESENTATION,
                    120,
                    2,
                    1,
                ),
                CaptchaBucketLimitV1(
                    CaptchaPurpose.RECOVER_RESPONSE,
                    CaptchaAction.ISSUE,
                    20,
                    1,
                    2,
                ),
                CaptchaBucketLimitV1(
                    CaptchaPurpose.RECOVER_RESPONSE,
                    CaptchaAction.VERIFY,
                    20,
                    1,
                    3,
                ),
                CaptchaBucketLimitV1(
                    CaptchaPurpose.RECOVER_RESPONSE,
                    CaptchaAction.FETCH_REPRESENTATION,
                    120,
                    2,
                    1,
                ),
            ),
        )

    def test_validated_profile_is_inert_and_non_authorizing(self) -> None:
        validated = validate_captcha_protocol_profile_v1(
            expected_captcha_protocol_profile_v1()
        )
        self.assertFalse(validated.generates_challenge)
        self.assertFalse(validated.validates_answer)
        self.assertFalse(validated.persists_challenge_record)
        self.assertFalse(validated.renders_media)
        self.assertFalse(validated.binds_to_network_identity)
        self.assertFalse(validated.uses_third_party_captcha)
        self.assertFalse(validated.authorizes_operation)
        self.assertFalse(validated.enables_protected_endpoint)
        self.assertFalse(
            validated.profile.abuse_control_profile.uses_network_identity_keys
        )
        self.assertFalse(
            validated.profile.production_gate_profile.production_enabled
        )
        self.assertTrue(
            validated
            .profile
            .representation_profile
            .audio_required_before_production
        )
        for field_name in (
            "challenge_id",
            "form_scope",
            "expected_answer",
            "submitted_answer",
            "request",
            "ip_address",
            "user_agent",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class CaptchaDescriptorValidationTests(SimpleTestCase):
    def test_identifier_validation_returns_only_shape(self) -> None:
        shape = validate_captcha_identifier_text_v1(
            "AAAAAAAAAAAAAAAAAAAAAA"
        )
        self.assertEqual(shape.raw_size_bytes, CAPTCHA_IDENTIFIER_RAW_BYTES)
        self.assertEqual(shape.encoded_length, CAPTCHA_IDENTIFIER_ENCODED_LENGTH)
        self.assertEqual(shape.alphabet, CAPTCHA_IDENTIFIER_ALPHABET)

        for candidate in (
            object(),
            "AAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAAAAAAAA/",
            "AAAAAAAAAAAAAAAAAAAAAé",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(CaptchaDescriptorRejected):
                    validate_captcha_identifier_text_v1(candidate)

    def test_answer_validation_is_strict_and_returns_only_shape(self) -> None:
        shape = validate_captcha_answer_text_v1("234ABC")
        self.assertEqual(shape.answer_length, CAPTCHA_ANSWER_LENGTH)
        self.assertEqual(shape.alphabet, CAPTCHA_ANSWER_ALPHABET)

        for candidate in (
            object(),
            "234AB",
            "234ABCD",
            "234abC",
            "234A0C",
            "234AIC",
            "234AOC",
            "234A C",
            "234AéC",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(CaptchaDescriptorRejected):
                    validate_captcha_answer_text_v1(candidate)

    def test_profile_rejects_changed_version_shapes_gates_and_identity_keys(
        self,
    ) -> None:
        valid = expected_captcha_protocol_profile_v1()
        changed_identifier = replace(
            valid.identifier_shape,
            encoded_length=CAPTCHA_IDENTIFIER_ENCODED_LENGTH + 1,
        )
        changed_answer = replace(
            valid.answer_shape,
            alphabet=frozenset("012345"),
        )
        changed_abuse = CaptchaAbuseControlProfileV1(
            bucket_limits=CAPTCHA_BUCKET_LIMITS_V1,
            uses_network_identity_keys=True,
        )
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(valid, identifier_shape=changed_identifier),
            replace(valid, answer_shape=changed_answer),
            replace(
                valid,
                purpose_profile=replace(
                    valid.purpose_profile,
                    allowed_purposes=tuple(reversed(CAPTCHA_PURPOSES_V1)),
                ),
            ),
            replace(
                valid,
                state_profile=replace(
                    valid.state_profile,
                    allowed_states=valid.state_profile.allowed_states
                    + (CaptchaChallengeState.READY,),
                ),
            ),
            replace(valid, abuse_control_profile=changed_abuse),
            replace(
                valid,
                production_gate_profile=replace(
                    valid.production_gate_profile,
                    production_enabled=True,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(CaptchaDescriptorRejected):
                    validate_captcha_protocol_profile_v1(candidate)

    def test_bucket_limit_mutations_are_rejected(self) -> None:
        valid = expected_captcha_protocol_profile_v1()
        weakened_bucket = CaptchaBucketLimitV1(
            CaptchaPurpose.SUBMIT_REPORT,
            CaptchaAction.VERIFY,
            200,
            10,
            1,
        )
        for candidate in (
            replace(
                valid,
                abuse_control_profile=replace(
                    valid.abuse_control_profile,
                    bucket_limits=(weakened_bucket,),
                ),
            ),
            replace(
                valid,
                abuse_control_profile=replace(
                    valid.abuse_control_profile,
                    bucket_limits=list(CAPTCHA_BUCKET_LIMITS_V1),
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(CaptchaDescriptorRejected):
                    validate_captcha_protocol_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        shape = CaptchaAnswerShapeV1(
            answer_length=CAPTCHA_ANSWER_LENGTH,
            alphabet=CAPTCHA_ANSWER_ALPHABET,
        )
        with self.assertRaises(FrozenInstanceError):
            shape.answer_length = 7

        validated = validate_captcha_protocol_profile_v1(
            expected_captcha_protocol_profile_v1()
        )
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.enables_protected_endpoint = True

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "CAPTCHA_SENTINEL"
        with self.assertRaises(CaptchaDescriptorRejected) as raised:
            validate_captcha_answer_text_v1(sentinel)
        self.assertEqual(str(raised.exception), "captcha_descriptor_rejected")
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
