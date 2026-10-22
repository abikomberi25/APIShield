"""In-memory rate limiter for OWASP API4:2023 Unrestricted Resource Consumption defense.

Implements a fixed-window rate limiter keyed by authenticated user ID (or IP as fallback).
Thread-safe using a simple lock. Bounded memory via automatic expiry of old windows.
Single-process only — state is not shared across workers.
"""

import threading
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

# Default rate limit policy (configurable per-instance for testing)
DEFAULT_REQUESTS_PER_WINDOW = 20   # max requests allowed in the window
DEFAULT_WINDOW_SECONDS = 60        # rolling window size in seconds


class RateLimiter:
    """Fixed-window rate limiter keyed by a string identity (user ID or IP).

    Each key gets its own independent fixed window. When the window expires,
    the counter resets. Excess requests beyond the limit are refused.

    Memory is bounded: stale windows (older than window_seconds) are pruned
    on each check to prevent unbounded growth.

    NOT suitable for multi-worker deployments — use Redis or a shared store
    for distributed rate limiting. This lab uses a single Uvicorn worker.
    """

    def __init__(
        self,
        requests_per_window: int = DEFAULT_REQUESTS_PER_WINDOW,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        # key → (window_start: datetime, count: int)
        self._windows: Dict[str, Tuple[datetime, int]] = {}

    def check_and_record(self, key: str) -> Tuple[bool, int]:
        """Check whether the key is within its rate limit and record the request.

        Returns (allowed: bool, requests_remaining: int).
        - If allowed=True, the request is counted and within the limit.
        - If allowed=False, the limit has been exceeded; request should be rejected.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune_stale(now)

            if key not in self._windows:
                # First request in a new window
                self._windows[key] = (now, 1)
                return True, self.requests_per_window - 1

            window_start, count = self._windows[key]
            elapsed = (now - window_start).total_seconds()

            if elapsed >= self.window_seconds:
                # Window expired — reset
                self._windows[key] = (now, 1)
                return True, self.requests_per_window - 1

            if count >= self.requests_per_window:
                # Limit exceeded within the current window
                return False, 0

            # Within window and within limit
            self._windows[key] = (window_start, count + 1)
            return True, self.requests_per_window - count - 1

    def get_window_reset_seconds(self, key: str) -> int:
        """Return seconds until the current window resets for the given key.

        Returns 0 if the key has no active window.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            if key not in self._windows:
                return 0
            window_start, _ = self._windows[key]
            elapsed = (now - window_start).total_seconds()
            remaining = self.window_seconds - elapsed
            return max(0, int(remaining))

    def reset_key(self, key: str) -> None:
        """Remove a key's rate-limit window. Used for test isolation."""
        with self._lock:
            self._windows.pop(key, None)

    def reset_all(self) -> None:
        """Clear all rate-limit windows. Used for test isolation between tests."""
        with self._lock:
            self._windows.clear()

    def _prune_stale(self, now: datetime) -> None:
        """Remove expired windows to bound memory usage. Must hold self._lock."""
        stale_keys = [
            key
            for key, (window_start, _) in self._windows.items()
            if (now - window_start).total_seconds() >= self.window_seconds
        ]
        for key in stale_keys:
            del self._windows[key]


# Global singleton instance for the application process
rate_limiter = RateLimiter()
