"""Deny-by-default boundaries for security controls that remain OPEN."""

from .errors import SecurityControlUnavailable, SecurityDependency
from .unavailable import (
    UnavailableAlertService,
    UnavailableAuditReceiptService,
    UnavailableCaptchaService,
    UnavailableFileSandbox,
    UnavailableKeyService,
    UnavailableRecoveryVerifier,
    UnavailableStepUpService,
)

__all__ = [
    "SecurityControlUnavailable",
    "SecurityDependency",
    "UnavailableAlertService",
    "UnavailableAuditReceiptService",
    "UnavailableCaptchaService",
    "UnavailableFileSandbox",
    "UnavailableKeyService",
    "UnavailableRecoveryVerifier",
    "UnavailableStepUpService",
]
