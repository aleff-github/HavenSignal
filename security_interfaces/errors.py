"""Controlled failure types for unavailable mandatory security controls."""

from enum import StrEnum


class SecurityDependency(StrEnum):
    """Allowlisted internal names; never populated from request data."""

    ALERT_SERVICE = "alert_service"
    AUDIT_RECEIPT_SERVICE = "audit_receipt_service"
    CAPTCHA_SERVICE = "captcha_service"
    FILE_SANDBOX = "file_sandbox"
    KEY_SERVICE = "key_service"
    RECOVERY_VERIFIER = "recovery_verifier"
    STEP_UP_SERVICE = "step_up_service"


class SecurityControlUnavailable(RuntimeError):
    """Signal that a protected operation must stop without a weaker fallback."""

    public_code = "security_control_unavailable"

    def __init__(self, dependency: SecurityDependency) -> None:
        self.dependency = dependency
        super().__init__(self.public_code)


class AuditDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert audit descriptor."""

    public_code = "audit_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class AlertDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert alert descriptor."""

    public_code = "alert_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class StepUpDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert step-up descriptor."""

    public_code = "step_up_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class RecoveryDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert recovery descriptor."""

    public_code = "recovery_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ResponseCryptoDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert response crypto descriptor."""

    public_code = "response_crypto_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)
