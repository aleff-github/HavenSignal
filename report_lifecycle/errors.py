class LifecycleTransitionDenied(Exception):
    """Controlled denial for every invalid lifecycle transition or binding."""

    def __init__(self) -> None:
        super().__init__("lifecycle_transition_denied")


class LifecyclePersistenceUnavailable(Exception):
    """Controlled denial while the PostgreSQL executor remains gated."""

    def __init__(self) -> None:
        super().__init__("lifecycle_persistence_unavailable")


class FinalizationOrchestrationUnavailable(Exception):
    """Controlled denial while protected finalization remains gated."""

    def __init__(self) -> None:
        super().__init__("finalization_orchestration_unavailable")


class DeletionOrchestrationUnavailable(Exception):
    """Controlled denial while protected deletion remains gated."""

    def __init__(self) -> None:
        super().__init__("deletion_orchestration_unavailable")


class ResponseRetentionOrchestrationUnavailable(Exception):
    """Controlled denial while protected response retention remains gated."""

    def __init__(self) -> None:
        super().__init__("response_retention_orchestration_unavailable")


class CleanupOrchestrationUnavailable(Exception):
    """Controlled denial while protected ciphertext cleanup remains gated."""

    def __init__(self) -> None:
        super().__init__("cleanup_orchestration_unavailable")


class MetadataRetentionOrchestrationUnavailable(Exception):
    """Controlled denial while terminal metadata retention remains gated."""

    def __init__(self) -> None:
        super().__init__("metadata_retention_orchestration_unavailable")


class AuditRetentionOrchestrationUnavailable(Exception):
    """Controlled denial while isolated audit retention remains gated."""

    def __init__(self) -> None:
        super().__init__("audit_retention_orchestration_unavailable")
