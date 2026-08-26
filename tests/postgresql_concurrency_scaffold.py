"""Inert, content-free scaffold for future PostgreSQL concurrency proof."""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from report_lifecycle.persistence import require_postgresql_transition_backend


PROFILE_VERSION = 1
MIN_CONTENDERS = 20
MAX_CONTENDERS = 100
MIN_PROCESSES = 2


class ConcurrencyScenario(StrEnum):
    ACTIVE_LEASE_PER_OPERATOR = "ACTIVE_LEASE_PER_OPERATOR"
    ACTIVE_LEASE_PER_REPORT = "ACTIVE_LEASE_PER_REPORT"
    ACTIVE_OPERATION_PER_REPORT = "ACTIVE_OPERATION_PER_REPORT"
    ACTIVE_REPORT_PER_OPERATOR = "ACTIVE_REPORT_PER_OPERATOR"
    STALE_LEASE_GENERATION = "STALE_LEASE_GENERATION"
    STALE_REPORT_VERSION = "STALE_REPORT_VERSION"


@dataclass(frozen=True, slots=True)
class ConcurrencyExpectation:
    maximum_successes: int
    requirement_ids: tuple[str, ...]


CONCURRENCY_EXPECTATIONS = MappingProxyType(
    {
        ConcurrencyScenario.ACTIVE_LEASE_PER_OPERATOR: ConcurrencyExpectation(
            maximum_successes=1,
            requirement_ids=("SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.ACTIVE_LEASE_PER_REPORT: ConcurrencyExpectation(
            maximum_successes=1,
            requirement_ids=("SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.ACTIVE_OPERATION_PER_REPORT: ConcurrencyExpectation(
            maximum_successes=1,
            requirement_ids=("SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR: ConcurrencyExpectation(
            maximum_successes=1,
            requirement_ids=("SEC-ACCESS-002", "SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.STALE_LEASE_GENERATION: ConcurrencyExpectation(
            maximum_successes=0,
            requirement_ids=("SEC-ACCESS-013", "SEC-ACCESS-014", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.STALE_REPORT_VERSION: ConcurrencyExpectation(
            maximum_successes=0,
            requirement_ids=("SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
    }
)


class PostgreSQLConcurrencyHarnessUnavailable(Exception):
    """Controlled denial while the reviewed multi-process runner is absent."""

    def __init__(self) -> None:
        super().__init__("postgresql_concurrency_harness_unavailable")


@dataclass(frozen=True, slots=True)
class _SyntheticConcurrencyCase:
    profile_version: int
    scenario: ConcurrencyScenario
    run_id: UUID
    contention_target_id: UUID
    contender_ids: tuple[UUID, ...]
    requested_process_count: int
    synchronized_start: bool

    def __post_init__(self) -> None:
        valid_identifiers = (
            type(self.run_id) is UUID
            and type(self.contention_target_id) is UUID
            and type(self.contender_ids) is tuple
            and all(type(value) is UUID for value in self.contender_ids)
            and len(set(self.contender_ids)) == len(self.contender_ids)
            and self.run_id not in self.contender_ids
            and self.contention_target_id not in self.contender_ids
            and self.run_id != self.contention_target_id
        )
        valid_shape = (
            type(self.profile_version) is int
            and self.profile_version == PROFILE_VERSION
            and type(self.scenario) is ConcurrencyScenario
            and type(self.requested_process_count) is int
            and MIN_PROCESSES
            <= self.requested_process_count
            <= len(self.contender_ids)
            and MIN_CONTENDERS <= len(self.contender_ids) <= MAX_CONTENDERS
            and self.synchronized_start is True
        )
        if not valid_identifiers or not valid_shape:
            raise PostgreSQLConcurrencyHarnessUnavailable()

    @property
    def contender_count(self) -> int:
        return len(self.contender_ids)

    @property
    def dedicated_connection_count(self) -> int:
        return len(self.contender_ids)

    @property
    def expectation(self) -> ConcurrencyExpectation:
        return CONCURRENCY_EXPECTATIONS[self.scenario]


def build_synthetic_concurrency_case(
    *,
    scenario: ConcurrencyScenario,
    contender_count: int = MIN_CONTENDERS,
    process_count: int = MIN_PROCESSES,
) -> _SyntheticConcurrencyCase:
    """Generate only ephemeral UUID metadata for one future test case."""

    if (
        type(scenario) is not ConcurrencyScenario
        or type(contender_count) is not int
        or not MIN_CONTENDERS <= contender_count <= MAX_CONTENDERS
        or type(process_count) is not int
        or not MIN_PROCESSES <= process_count <= contender_count
    ):
        raise PostgreSQLConcurrencyHarnessUnavailable()
    return _SyntheticConcurrencyCase(
        profile_version=PROFILE_VERSION,
        scenario=scenario,
        run_id=uuid4(),
        contention_target_id=uuid4(),
        contender_ids=tuple(uuid4() for _ in range(contender_count)),
        requested_process_count=process_count,
        synchronized_start=True,
    )


def run_postgresql_concurrency_case(
    *,
    case: _SyntheticConcurrencyCase,
    using: str = "default",
) -> None:
    """Always deny until the PostgreSQL runner and executor are reviewed."""

    if type(case) is not _SyntheticConcurrencyCase or type(using) is not str:
        raise PostgreSQLConcurrencyHarnessUnavailable()
    try:
        require_postgresql_transition_backend(using=using)
    except Exception:
        # Dependency/configuration failures must not leak connection details or
        # accidentally turn an unavailable harness into a partial test run.
        raise PostgreSQLConcurrencyHarnessUnavailable() from None

    # Backend shape alone is not concurrency evidence. Enabling work here
    # requires the reviewed executor, lock order, isolation profile, barrier,
    # independent connections/processes, cleanup, and result assertions.
    raise PostgreSQLConcurrencyHarnessUnavailable()
