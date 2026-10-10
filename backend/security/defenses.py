"""Runtime defense toggle configuration and state management for APIShield."""

from typing import Any, Mapping

# Default startup defense configuration (all OFF per SPEC.md Section 4)
DEFAULT_DEFENSES: dict[str, bool] = {
    "bola": False,
    "auth_hardening": False,
    "schema_validation": False,
    "rate_limit": False,
    "rbac": False,
}


class DefenseManager:
    """Manages in-memory runtime defense toggle flags.

    Provides deterministic startup defaults and thread-safe inspection/updates.
    State is kept in-memory to ensure low latency and clean test isolation.
    """

    def __init__(self, initial_defenses: Mapping[str, bool] | None = None) -> None:
        defaults = initial_defenses if initial_defenses is not None else DEFAULT_DEFENSES
        self._defenses: dict[str, bool] = dict(defaults)

    def get_defenses(self) -> dict[str, bool]:
        """Return a copy of the current defense toggle state."""
        return dict(self._defenses)

    def update_defenses(self, updates: Mapping[str, Any]) -> dict[str, bool]:
        """Update defense flags with the provided mapping.

        Validates that all keys are known defense flags and all values are booleans.
        Raises ValueError if an unknown flag or non-boolean value is encountered.
        """
        for key, value in updates.items():
            if key not in DEFAULT_DEFENSES:
                raise ValueError(f"Unknown defense flag: {key}")
            if not isinstance(value, bool):
                raise ValueError(
                    f"Invalid value for defense flag '{key}': expected bool, got {type(value).__name__}"
                )

        for key, value in updates.items():
            self._defenses[key] = value

        return self.get_defenses()

    def reset(self) -> None:
        """Reset all defense flags to default values (all OFF)."""
        self._defenses = dict(DEFAULT_DEFENSES)


# Global singleton instance for the application process
defense_manager = DefenseManager()
