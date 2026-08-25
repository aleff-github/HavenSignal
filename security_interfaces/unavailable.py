"""Fail-closed placeholders for security service families with OPEN gates."""

from typing import ClassVar, Never

from .errors import SecurityControlUnavailable, SecurityDependency


class _UnavailableDependency:
    dependency: ClassVar[SecurityDependency]

    def _deny(self) -> Never:
        raise SecurityControlUnavailable(self.dependency)


class UnavailableAuditReceiptService(_UnavailableDependency):
    """No audit append or receipt capability is configured."""

    dependency = SecurityDependency.AUDIT_RECEIPT_SERVICE

    def obtain_pre_action_receipt(self) -> Never:
        self._deny()

    def append_outcome(self) -> Never:
        self._deny()


class UnavailableKeyService(_UnavailableDependency):
    """No cryptographic key capability is configured."""

    dependency = SecurityDependency.KEY_SERVICE

    def protect_new_submission(self) -> Never:
        self._deny()

    def authorize_report_use(self) -> Never:
        self._deny()

    def protect_response(self) -> Never:
        self._deny()

    def authorize_response_use(self) -> Never:
        self._deny()

    def destroy_object_key(self) -> Never:
        self._deny()


class UnavailableCaptchaService(_UnavailableDependency):
    """No mandatory self-hosted challenge capability is configured."""

    dependency = SecurityDependency.CAPTCHA_SERVICE

    def generate_challenge(self) -> Never:
        self._deny()

    def validate_challenge(self) -> Never:
        self._deny()


class UnavailableStepUpService(_UnavailableDependency):
    """No operation-bound step-up authorization is configured."""

    dependency = SecurityDependency.STEP_UP_SERVICE

    def authorize_operation(self) -> Never:
        self._deny()

    def consume_authorization(self) -> Never:
        self._deny()


class UnavailableRecoveryVerifier(_UnavailableDependency):
    """No Recovery Secret verifier construction is configured."""

    dependency = SecurityDependency.RECOVERY_VERIFIER

    def authorize_recovery(self) -> Never:
        self._deny()


class UnavailableFileSandbox(_UnavailableDependency):
    """No attachment parser or safe-representation worker is configured."""

    dependency = SecurityDependency.FILE_SANDBOX

    def create_safe_representation(self) -> Never:
        self._deny()


class UnavailableAlertService(_UnavailableDependency):
    """No approved alert delivery transport is configured."""

    dependency = SecurityDependency.ALERT_SERVICE

    def deliver_allowlisted_alert(self) -> Never:
        self._deny()
