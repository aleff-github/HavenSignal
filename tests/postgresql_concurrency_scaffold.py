"""Synthetic PostgreSQL concurrency acceptance harness for metadata fences."""

from datetime import timedelta
from dataclasses import dataclass
from enum import StrEnum
from multiprocessing import get_context
from queue import Empty
from time import monotonic
from types import MappingProxyType
from uuid import UUID, uuid4, uuid5

from django.db import IntegrityError, connections, transaction
from django.utils import timezone

from report_lifecycle.bindings import (
    ReportBindingSnapshot,
    SecurityOperationCommand,
    ValidatedSecurityOperationBinding,
    validate_inert_security_operation_binding,
)
from report_lifecycle.errors import LifecyclePersistenceUnavailable
from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.persistence import (
    PreparedSecurityOperation,
    abort_prepared_security_operation,
    activate_prepared_security_operation,
    persist_validated_security_operation,
    require_postgresql_transition_backend,
)
from report_lifecycle.states import (
    ReportState,
    SecurityOperationKind,
    SecurityOperationState,
)


PROFILE_VERSION = 1
MIN_CONTENDERS = 20
MAX_CONTENDERS = 100
MIN_PROCESSES = 2
PROCESS_DEADLINE_SECONDS = 30


class ConcurrencyScenario(StrEnum):
    ACTIVE_LEASE_PER_OPERATOR = "ACTIVE_LEASE_PER_OPERATOR"
    ACTIVE_LEASE_PER_REPORT = "ACTIVE_LEASE_PER_REPORT"
    ACTIVE_OPERATION_PER_REPORT = "ACTIVE_OPERATION_PER_REPORT"
    PREPARED_OPERATION_PER_REPORT = "PREPARED_OPERATION_PER_REPORT"
    PREPARED_OPERATION_ACTIVATION = "PREPARED_OPERATION_ACTIVATION"
    PREPARED_OPERATION_DECISION = "PREPARED_OPERATION_DECISION"
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
        ConcurrencyScenario.PREPARED_OPERATION_PER_REPORT: ConcurrencyExpectation(
            maximum_successes=1,
            requirement_ids=("SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.PREPARED_OPERATION_ACTIVATION: ConcurrencyExpectation(
            maximum_successes=1,
            requirement_ids=("SEC-ACCESS-010", "SEC-ACCESS-015"),
        ),
        ConcurrencyScenario.PREPARED_OPERATION_DECISION: ConcurrencyExpectation(
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


class ConcurrencyOutcome(StrEnum):
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ConcurrencyResult:
    scenario: ConcurrencyScenario
    contender_count: int
    committed_count: int
    rejected_count: int
    failed_count: int


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
) -> ConcurrencyResult:
    """Run one synthetic test case without exposing a production executor."""

    if (
        type(case) is not _SyntheticConcurrencyCase
        or type(using) is not str
        or case.requested_process_count != case.contender_count
    ):
        raise PostgreSQLConcurrencyHarnessUnavailable()
    try:
        require_postgresql_transition_backend(using=using)
    except Exception:
        # Dependency/configuration failures must not leak connection details or
        # accidentally turn an unavailable harness into a partial test run.
        raise PostgreSQLConcurrencyHarnessUnavailable() from None
    if not _is_postgresql_backend(using):
        raise PostgreSQLConcurrencyHarnessUnavailable()

    _prepare_case(case=case, using=using)
    context = get_context("fork")
    barrier = context.Barrier(case.contender_count)
    results = context.Queue()
    processes = [
        context.Process(
            target=_run_contender,
            args=(
                case.scenario.value,
                str(case.run_id),
                str(case.contention_target_id),
                str(contender_id),
                ordinal,
                using,
                barrier,
                results,
            ),
        )
        for ordinal, contender_id in enumerate(case.contender_ids)
    ]
    connections.close_all()
    try:
        for process in processes:
            process.start()
        deadline = monotonic() + PROCESS_DEADLINE_SECONDS
        for process in processes:
            process.join(max(0.0, deadline - monotonic()))
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()

        outcomes: list[ConcurrencyOutcome] = []
        while len(outcomes) < case.contender_count:
            try:
                outcomes.append(ConcurrencyOutcome(results.get(timeout=1)))
            except (Empty, ValueError):
                break
        missing = case.contender_count - len(outcomes)
        failed = outcomes.count(ConcurrencyOutcome.FAILED) + missing
        return ConcurrencyResult(
            scenario=case.scenario,
            contender_count=case.contender_count,
            committed_count=outcomes.count(ConcurrencyOutcome.COMMITTED),
            rejected_count=outcomes.count(ConcurrencyOutcome.REJECTED),
            failed_count=failed,
        )
    finally:
        results.close()
        results.join_thread()
        connections.close_all()
        _cleanup_case(case=case, using=using)


def _is_postgresql_backend(using: str) -> bool:
    return connections[using].vendor == "postgresql"


def _prepare_case(*, case: _SyntheticConcurrencyCase, using: str) -> None:
    report_ids: tuple[UUID, ...]
    if case.scenario is ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR:
        report_ids = ()
    elif case.scenario is ConcurrencyScenario.ACTIVE_LEASE_PER_OPERATOR:
        report_ids = case.contender_ids
    else:
        report_ids = (case.contention_target_id,)
    Report.objects.using(using).bulk_create(
        [Report(id=report_id) for report_id in report_ids]
    )
    if case.scenario is ConcurrencyScenario.STALE_REPORT_VERSION:
        Report.objects.using(using).filter(id=case.contention_target_id).update(
            state_version=1
        )
    if case.scenario is ConcurrencyScenario.STALE_LEASE_GENERATION:
        Report.objects.using(using).filter(id=case.contention_target_id).update(
            current_lease_generation=1
        )
    if case.scenario in (
        ConcurrencyScenario.PREPARED_OPERATION_ACTIVATION,
        ConcurrencyScenario.PREPARED_OPERATION_DECISION,
    ):
        command = _activation_command(
            run_id=case.run_id,
            report_id=case.contention_target_id,
        )
        binding = _activation_binding(command=command)
        persist_validated_security_operation(binding=binding, using=using)


def _cleanup_case(*, case: _SyntheticConcurrencyCase, using: str) -> None:
    report_ids = (*case.contender_ids, case.contention_target_id)
    SecurityOperation.objects.using(using).filter(
        report_id__in=report_ids
    ).delete()
    ReportLease.objects.using(using).filter(report_id__in=report_ids).delete()
    Report.objects.using(using).filter(id__in=report_ids).delete()


def _run_contender(
    scenario_value: str,
    run_id_value: str,
    target_id_value: str,
    contender_id_value: str,
    ordinal: int,
    using: str,
    barrier: object,
    results: object,
) -> None:
    connections.close_all()
    outcome = ConcurrencyOutcome.FAILED
    try:
        scenario = ConcurrencyScenario(scenario_value)
        run_id = UUID(run_id_value)
        target_id = UUID(target_id_value)
        contender_id = UUID(contender_id_value)
        barrier.wait(timeout=PROCESS_DEADLINE_SECONDS)
        with transaction.atomic(using=using):
            committed = _attempt_case_write(
                scenario=scenario,
                run_id=run_id,
                target_id=target_id,
                contender_id=contender_id,
                ordinal=ordinal,
                using=using,
            )
        outcome = (
            ConcurrencyOutcome.COMMITTED
            if committed
            else ConcurrencyOutcome.REJECTED
        )
    except (IntegrityError, LifecyclePersistenceUnavailable):
        outcome = ConcurrencyOutcome.REJECTED
    except Exception:
        outcome = ConcurrencyOutcome.FAILED
    finally:
        connections.close_all()
        results.put(outcome.value)


def _attempt_case_write(
    *,
    scenario: ConcurrencyScenario,
    run_id: UUID,
    target_id: UUID,
    contender_id: UUID,
    ordinal: int,
    using: str,
) -> bool:
    now = timezone.now()
    if scenario is ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR:
        Report.objects.using(using).bulk_create(
            [
                Report(
                    id=contender_id,
                    state=ReportState.CLAIMED,
                    active_operator_id=target_id,
                    claimed_at=now,
                    claim_expires_at=now + timedelta(hours=1),
                )
            ]
        )
        return True
    if scenario is ConcurrencyScenario.ACTIVE_LEASE_PER_REPORT:
        ReportLease.objects.using(using).create(
            id=contender_id,
            report_id=target_id,
            operator_id=contender_id,
            generation=ordinal + 1,
            opened_at=now,
            last_activity_at=now,
            absolute_expires_at=now + timedelta(hours=1),
        )
        return True
    if scenario is ConcurrencyScenario.ACTIVE_LEASE_PER_OPERATOR:
        ReportLease.objects.using(using).create(
            id=uuid5(run_id, contender_id.hex),
            report_id=contender_id,
            operator_id=target_id,
            generation=1,
            opened_at=now,
            last_activity_at=now,
            absolute_expires_at=now + timedelta(hours=1),
        )
        return True
    if scenario is ConcurrencyScenario.ACTIVE_OPERATION_PER_REPORT:
        SecurityOperation.objects.using(using).bulk_create(
            [
                SecurityOperation(
                    id=contender_id,
                    report_id=target_id,
                    kind=SecurityOperationKind.REOPEN_REPORT,
                    state=SecurityOperationState.ACTIVE,
                    bound_report_version=0,
                    fence_token=ordinal + 1,
                    idempotency_id=uuid5(run_id, f"idempotency:{contender_id.hex}"),
                    actor_id=contender_id,
                    activated_at=now,
                )
            ]
        )
        return True
    if scenario is ConcurrencyScenario.PREPARED_OPERATION_PER_REPORT:
        command = SecurityOperationCommand(
            operation_id=contender_id,
            idempotency_id=uuid5(run_id, f"prepared:{contender_id.hex}"),
            kind=SecurityOperationKind.DELETE_REPORT_FLOOD,
            report_id=target_id,
            expected_report_version=0,
            actor_id=contender_id,
        )
        binding = validate_inert_security_operation_binding(
            command=command,
            report=ReportBindingSnapshot(
                report_id=target_id,
                state=ReportState.SEALED,
                state_version=0,
                current_lease_generation=0,
                active_operator_id=None,
            ),
            lease=None,
        )
        persist_validated_security_operation(binding=binding, using=using)
        return True
    if scenario is ConcurrencyScenario.PREPARED_OPERATION_ACTIVATION:
        command = _activation_command(run_id=run_id, report_id=target_id)
        binding = _activation_binding(command=command)
        prepared = PreparedSecurityOperation(
            operation_id=command.operation_id,
            report_id=command.report_id,
            idempotency_id=command.idempotency_id,
            state=SecurityOperationState.PREPARED,
            bound_report_version=0,
            fence_token=1,
            lease_id=None,
            lease_generation=None,
        )
        activate_prepared_security_operation(
            binding=binding,
            prepared=prepared,
            using=using,
        )
        return True
    if scenario is ConcurrencyScenario.PREPARED_OPERATION_DECISION:
        command = _activation_command(run_id=run_id, report_id=target_id)
        binding = _activation_binding(command=command)
        prepared = PreparedSecurityOperation(
            operation_id=command.operation_id,
            report_id=command.report_id,
            idempotency_id=command.idempotency_id,
            state=SecurityOperationState.PREPARED,
            bound_report_version=0,
            fence_token=1,
            lease_id=None,
            lease_generation=None,
        )
        if ordinal % 2 == 0:
            activate_prepared_security_operation(
                binding=binding,
                prepared=prepared,
                using=using,
            )
        else:
            abort_prepared_security_operation(
                binding=binding,
                prepared=prepared,
                using=using,
            )
        return True
    if scenario is ConcurrencyScenario.STALE_REPORT_VERSION:
        return (
            Report.objects.using(using)
            .filter(id=target_id, state_version=0)
            .update(state_version=2)
            == 1
        )
    if scenario is ConcurrencyScenario.STALE_LEASE_GENERATION:
        return (
            Report.objects.using(using)
            .filter(id=target_id, current_lease_generation=0)
            .update(current_lease_generation=2)
            == 1
        )
    return False


def _activation_command(
    *,
    run_id: UUID,
    report_id: UUID,
) -> SecurityOperationCommand:
    return SecurityOperationCommand(
        operation_id=run_id,
        idempotency_id=uuid5(run_id, "activation"),
        kind=SecurityOperationKind.DELETE_REPORT_FLOOD,
        report_id=report_id,
        expected_report_version=0,
        actor_id=run_id,
    )


def _activation_binding(
    *,
    command: SecurityOperationCommand,
) -> ValidatedSecurityOperationBinding:
    return validate_inert_security_operation_binding(
        command=command,
        report=ReportBindingSnapshot(
            report_id=command.report_id,
            state=ReportState.SEALED,
            state_version=0,
            current_lease_generation=0,
            active_operator_id=None,
        ),
        lease=None,
    )
