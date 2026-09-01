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


class AttachmentAdmissionDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert attachment descriptor."""

    public_code = "attachment_admission_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class CaptchaDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert CAPTCHA descriptor."""

    public_code = "captcha_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class FileSandboxDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert file-sandbox descriptor."""

    public_code = "file_sandbox_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class StepUpDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert step-up descriptor."""

    public_code = "step_up_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionAuditDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert submission-audit descriptor."""

    public_code = "submission_audit_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionAcceptanceCheckpointDescriptorRejected(ValueError):
    """Controlled rejection for invalid inert acceptance-checkpoint metadata."""

    public_code = "submission_acceptance_checkpoint_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionAttemptCredentialDescriptorRejected(ValueError):
    """Controlled rejection for invalid inert attempt-credential metadata."""

    public_code = "submission_attempt_credential_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionReconciliationDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert reconciliation descriptor."""

    public_code = "submission_reconciliation_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionRetryDescriptorRejected(ValueError):
    """Controlled rejection for invalid inert retry/outcome metadata."""

    public_code = "submission_retry_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionCredentialResponseDescriptorRejected(ValueError):
    """Controlled rejection for invalid inert credential-response metadata."""

    public_code = "submission_credential_response_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionFailureDescriptorRejected(ValueError):
    """Controlled rejection for invalid inert submission-failure metadata."""

    public_code = "submission_failure_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SubmissionIdempotencyDescriptorRejected(ValueError):
    """Controlled rejection for invalid inert submission-idempotency metadata."""

    public_code = "submission_idempotency_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class RecoveryDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert recovery descriptor."""

    public_code = "recovery_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class RequestAdmissionDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert request-admission descriptor."""

    public_code = "request_admission_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ReportCryptoDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert report crypto descriptor."""

    public_code = "report_crypto_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ReportFrameDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert report frame descriptor."""

    public_code = "report_frame_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ReportSchemaDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert report schema descriptor."""

    public_code = "report_schema_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ReportTextDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert report text descriptor."""

    public_code = "report_text_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class SafeViewDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert safe-view descriptor."""

    public_code = "safe_view_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ResponseCryptoDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert response crypto descriptor."""

    public_code = "response_crypto_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ResponseTextDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert response text descriptor."""

    public_code = "response_text_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)


class ResponseSchemaDescriptorRejected(ValueError):
    """Controlled rejection for an invalid inert response schema descriptor."""

    public_code = "response_schema_descriptor_rejected"

    def __init__(self) -> None:
        super().__init__(self.public_code)
