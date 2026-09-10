"""Fail-closed tests for the local PostgreSQL restart probe."""

from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

from django.test import SimpleTestCase

from tests.postgresql_restart_probe import (
    _probe_identifiers,
    main,
)


class PostgreSQLRestartProbeTests(SimpleTestCase):
    def test_probe_identifiers_are_deterministic_and_purpose_separated(self) -> None:
        probe_id = uuid4()
        first = _probe_identifiers(probe_id)
        second = _probe_identifiers(probe_id)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4)
        self.assertEqual(len(set(first)), 4)
        self.assertNotIn(probe_id, first)

    def test_invalid_action_or_identifier_never_reaches_backend(self) -> None:
        invalid_arguments = (
            [],
            ["prepare"],
            ["unknown", str(uuid4())],
            ["prepare", "not-a-uuid"],
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                stderr = StringIO()
                with (
                    patch(
                        "tests.postgresql_restart_probe.require_postgresql_transition_backend"
                    ) as backend,
                    redirect_stderr(stderr),
                ):
                    result = main(arguments)
                backend.assert_not_called()
                self.assertIn(result, {1, 2})
                self.assertNotIn("not-a-uuid", stderr.getvalue())

    def test_backend_failure_returns_only_controlled_error(self) -> None:
        sentinel = "DATABASE_CONFIGURATION_SENTINEL"
        stderr = StringIO()
        with (
            patch(
                "tests.postgresql_restart_probe.require_postgresql_transition_backend",
                side_effect=RuntimeError(sentinel),
            ),
            redirect_stderr(stderr),
        ):
            result = main(["verify", str(uuid4())])
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "postgresql_restart_probe_unavailable\n")
        self.assertNotIn(sentinel, stderr.getvalue())
