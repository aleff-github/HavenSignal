"""Content-free PostgreSQL restart probe for the local Docker test profile."""

import sys
from uuid import UUID, uuid5

import django
from django.db import connections, transaction


django.setup()

from report_lifecycle.bindings import (  # noqa: E402
    ReportBindingSnapshot,
    SecurityOperationCommand,
    validate_inert_security_operation_binding,
)
from report_lifecycle.models import Report, SecurityOperation  # noqa: E402
from report_lifecycle.persistence import (  # noqa: E402
    load_prepared_security_operation,
    persist_validated_security_operation,
    require_postgresql_transition_backend,
)
from report_lifecycle.states import (  # noqa: E402
    ReportState,
    SecurityOperationKind,
    SecurityOperationState,
)


class PostgreSQLRestartProbeUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("postgresql_restart_probe_unavailable")


def _probe_identifiers(probe_id: UUID) -> tuple[UUID, UUID, UUID, UUID]:
    return (
        uuid5(probe_id, "report"),
        uuid5(probe_id, "operation"),
        uuid5(probe_id, "idempotency"),
        uuid5(probe_id, "actor"),
    )


def _prepare(probe_id: UUID) -> None:
    report_id, operation_id, idempotency_id, actor_id = _probe_identifiers(probe_id)
    with transaction.atomic():
        report = Report.objects.create(id=report_id)
        command = SecurityOperationCommand(
            operation_id=operation_id,
            idempotency_id=idempotency_id,
            kind=SecurityOperationKind.DELETE_REPORT_FLOOD,
            report_id=report_id,
            expected_report_version=0,
            actor_id=actor_id,
        )
        binding = validate_inert_security_operation_binding(
            command=command,
            report=ReportBindingSnapshot(
                report_id=report.id,
                state=ReportState(report.state),
                state_version=report.state_version,
                current_lease_generation=report.current_lease_generation,
                active_operator_id=report.active_operator_id,
            ),
            lease=None,
        )
        prepared = persist_validated_security_operation(binding=binding)
        if (
            prepared.operation_id != operation_id
            or prepared.report_id != report_id
            or prepared.idempotency_id != idempotency_id
            or prepared.state is not SecurityOperationState.PREPARED
            or prepared.bound_report_version != 0
            or prepared.fence_token != 1
            or prepared.lease_id is not None
            or prepared.lease_generation is not None
        ):
            raise PostgreSQLRestartProbeUnavailable()


def _verify(probe_id: UUID) -> None:
    report_id, operation_id, idempotency_id, _actor_id = _probe_identifiers(probe_id)
    connections.close_all()
    prepared = load_prepared_security_operation(operation_id=operation_id)
    report = Report.objects.get(id=report_id)
    operation = SecurityOperation.objects.get(id=operation_id, report=report)
    if (
        prepared.operation_id != operation_id
        or prepared.report_id != report_id
        or prepared.idempotency_id != idempotency_id
        or prepared.state is not SecurityOperationState.PREPARED
        or report.state != ReportState.SEALED
        or report.state_version != 0
        or report.current_lease_generation != 0
        or report.active_operator_id is not None
        or operation.state != SecurityOperationState.PREPARED
        or operation.state_version != 0
        or operation.activated_at is not None
        or operation.terminal_at is not None
    ):
        raise PostgreSQLRestartProbeUnavailable()


def _cleanup(probe_id: UUID) -> None:
    report_id, operation_id, _idempotency_id, _actor_id = _probe_identifiers(probe_id)
    with transaction.atomic():
        SecurityOperation.objects.filter(id=operation_id).delete()
        Report.objects.filter(id=report_id).delete()


def main(arguments: list[str]) -> int:
    if len(arguments) != 2 or arguments[0] not in {"prepare", "verify", "cleanup"}:
        return 2
    try:
        probe_id = UUID(arguments[1])
        require_postgresql_transition_backend()
        if connections["default"].vendor != "postgresql":
            raise PostgreSQLRestartProbeUnavailable()
        {"prepare": _prepare, "verify": _verify, "cleanup": _cleanup}[
            arguments[0]
        ](probe_id)
    except Exception:
        print("postgresql_restart_probe_unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
