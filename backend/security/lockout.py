"""In-memory failed login attempt tracker for Broken Authentication defense."""

import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional


LOCKOUT_MAX_ATTEMPTS = 5        # failed attempts before lockout
LOCKOUT_WINDOW_SECONDS = 300    # 5-minute rolling window
LOCKOUT_DURATION_SECONDS = 300  # 5-minute lockout duration


class LoginAttemptTracker:
    """Thread-safe in-memory tracker for failed login attempts per username.

    Tracks failed login attempts within a rolling time window.
    Locks accounts temporarily after exceeding the threshold.
    Each username is tracked independently.
    Never stores passwords or tokens.
    """

    def __init__(
        self,
        max_attempts: int = LOCKOUT_MAX_ATTEMPTS,
        window_seconds: int = LOCKOUT_WINDOW_SECONDS,
        lockout_seconds: int = LOCKOUT_DURATION_SECONDS,
    ) -> None:
        self._max_attempts = max_attempts
        self._window = timedelta(seconds=window_seconds)
        self._lockout_duration = timedelta(seconds=lockout_seconds)
        self._lock = threading.Lock()
        # username -> list of UTC datetimes of recent failures
        self._failures: Dict[str, List[datetime]] = {}
        # username -> UTC datetime when lockout expires (None if not locked)
        self._lockout_until: Dict[str, datetime] = {}

    def _prune_old_failures(self, username: str) -> None:
        """Remove failure timestamps older than the rolling window (caller must hold lock)."""
        now = datetime.now(timezone.utc)
        cutoff = now - self._window
        self._failures[username] = [
            ts for ts in self._failures.get(username, []) if ts > cutoff
        ]

    def record_failure(self, username: str) -> None:
        """Record one failed login attempt for the given username.

        Never stores or logs the attempted password.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            self._prune_old_failures(username)
            self._failures.setdefault(username, []).append(now)
            # If failures in window now exceed the threshold, set lockout
            if len(self._failures[username]) >= self._max_attempts:
                self._lockout_until[username] = now + self._lockout_duration

    def record_success(self, username: str) -> None:
        """Record a successful login — clears failure history and any active lockout."""
        with self._lock:
            self._failures.pop(username, None)
            self._lockout_until.pop(username, None)

    def is_locked_out(self, username: str) -> bool:
        """Return True if the account is currently under a lockout."""
        with self._lock:
            until = self._lockout_until.get(username)
            if until is None:
                return False
            if datetime.now(timezone.utc) < until:
                return True
            # Lockout has expired — clear it
            self._lockout_until.pop(username, None)
            self._failures.pop(username, None)
            return False

    def get_lockout_remaining(self, username: str) -> Optional[int]:
        """Return seconds remaining in the lockout, or None if not locked out."""
        with self._lock:
            until = self._lockout_until.get(username)
            if until is None:
                return None
            remaining = (until - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                self._lockout_until.pop(username, None)
                self._failures.pop(username, None)
                return None
            return int(remaining)

    def reset_user(self, username: str) -> None:
        """Clear all state for a specific username (for test isolation)."""
        with self._lock:
            self._failures.pop(username, None)
            self._lockout_until.pop(username, None)

    def reset_all(self) -> None:
        """Clear all tracked state (for test isolation)."""
        with self._lock:
            self._failures.clear()
            self._lockout_until.clear()


# Global singleton
login_tracker = LoginAttemptTracker()
