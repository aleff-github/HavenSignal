from dataclasses import dataclass

from django.db import connections

from .bindings import ValidatedSecurityOperationBinding
from .errors import LifecyclePersistenceUnavailable


@dataclass(frozen=True, slots=True)
class LifecycleBackendCapabilities:
    alias: str
    vendor: str
    supports_transactions: bool
    supports_row_locks: bool
    supports_partial_indexes: bool


def inspect_lifecycle_backend(*, using: str = "default") -> LifecycleBackendCapabilities:
    connection = connections[using]
    return LifecycleBackendCapabilities(
        alias=using,
        vendor=connection.vendor,
        supports_transactions=connection.features.supports_transactions,
        supports_row_locks=connection.features.has_select_for_update,
        supports_partial_indexes=connection.features.supports_partial_indexes,
    )


def require_postgresql_transition_backend(
    *,
    using: str = "default",
) -> LifecycleBackendCapabilities:
    capabilities = inspect_lifecycle_backend(using=using)
    if (
        capabilities.vendor != "postgresql"
        or not capabilities.supports_transactions
        or not capabilities.supports_row_locks
        or not capabilities.supports_partial_indexes
    ):
        raise LifecyclePersistenceUnavailable()
    return capabilities


def persist_validated_security_operation(
    *,
    binding: ValidatedSecurityOperationBinding,
    using: str = "default",
) -> None:
    """Fail closed until a production-equivalent PostgreSQL executor is reviewed."""

    if not isinstance(binding, ValidatedSecurityOperationBinding):
        raise LifecyclePersistenceUnavailable()
    require_postgresql_transition_backend(using=using)

    # Backend capability checks are necessary but not sufficient. No ORM write
    # is enabled until lock ordering and multi-process PostgreSQL tests pass.
    raise LifecyclePersistenceUnavailable()
