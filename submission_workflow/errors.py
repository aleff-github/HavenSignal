class SubmissionTransitionDenied(RuntimeError):
    """Controlled fail-closed result for invalid or stale state changes."""

    public_code = "submission_transition_denied"

    def __str__(self) -> str:
        return self.public_code
