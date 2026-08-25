"""Architecture-conformance tests for fail-closed security placeholders."""

from collections.abc import Callable
from typing import Never

from django.conf import settings
from django.test import SimpleTestCase

from security_interfaces import (
    SecurityControlUnavailable,
    SecurityDependency,
    UnavailableAlertService,
    UnavailableAuditReceiptService,
    UnavailableCaptchaService,
    UnavailableFileSandbox,
    UnavailableKeyService,
    UnavailableRecoveryVerifier,
    UnavailableStepUpService,
)


SERVICE_METHODS: tuple[
    tuple[object, SecurityDependency, tuple[str, ...]], ...
] = (
    (
        UnavailableAuditReceiptService(),
        SecurityDependency.AUDIT_RECEIPT_SERVICE,
        ("obtain_pre_action_receipt", "append_outcome"),
    ),
    (
        UnavailableKeyService(),
        SecurityDependency.KEY_SERVICE,
        (
            "protect_new_submission",
            "authorize_report_use",
            "protect_response",
            "authorize_response_use",
            "destroy_object_key",
        ),
    ),
    (
        UnavailableCaptchaService(),
        SecurityDependency.CAPTCHA_SERVICE,
        ("generate_challenge", "validate_challenge"),
    ),
    (
        UnavailableStepUpService(),
        SecurityDependency.STEP_UP_SERVICE,
        ("authorize_operation", "consume_authorization"),
    ),
    (
        UnavailableRecoveryVerifier(),
        SecurityDependency.RECOVERY_VERIFIER,
        ("authorize_recovery",),
    ),
    (
        UnavailableFileSandbox(),
        SecurityDependency.FILE_SANDBOX,
        ("create_safe_representation",),
    ),
    (
        UnavailableAlertService(),
        SecurityDependency.ALERT_SERVICE,
        ("deliver_allowlisted_alert",),
    ),
)


class SecurityInterfaceFailureTests(SimpleTestCase):
    def test_every_public_operation_fails_closed(self) -> None:
        for service, dependency, method_names in SERVICE_METHODS:
            for method_name in method_names:
                with self.subTest(service=type(service).__name__, method=method_name):
                    method: Callable[[], Never] = getattr(service, method_name)
                    with self.assertRaises(SecurityControlUnavailable) as raised:
                        method()

                    self.assertEqual(raised.exception.dependency, dependency)
                    self.assertEqual(
                        str(raised.exception),
                        SecurityControlUnavailable.public_code,
                    )

    def test_placeholders_expose_only_the_reviewed_narrow_operations(self) -> None:
        for service, _dependency, expected_methods in SERVICE_METHODS:
            with self.subTest(service=type(service).__name__):
                public_methods = {
                    name
                    for name in dir(service)
                    if not name.startswith("_") and callable(getattr(service, name))
                }
                self.assertEqual(public_methods, set(expected_methods))

    def test_key_placeholder_has_no_general_unwrap_or_decrypt_api(self) -> None:
        key_service = UnavailableKeyService()

        for forbidden_name in (
            "decrypt_report",
            "get_report_key",
            "unwrap_any_dek",
            "unwrap_dek",
        ):
            with self.subTest(name=forbidden_name):
                self.assertFalse(hasattr(key_service, forbidden_name))

    def test_placeholders_are_not_django_applications(self) -> None:
        self.assertNotIn("security_interfaces", settings.INSTALLED_APPS)
