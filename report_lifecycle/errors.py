class LifecycleTransitionDenied(Exception):
    """Controlled denial for every invalid lifecycle transition or binding."""

    def __init__(self) -> None:
        super().__init__("lifecycle_transition_denied")
