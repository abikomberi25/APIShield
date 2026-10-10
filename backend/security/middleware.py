"""Security gateway middleware for APIShield."""

import time
from typing import Awaitable, Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityGatewayMiddleware(BaseHTTPMiddleware):
    """Minimal, high-performance security gateway middleware.

    Focuses strictly on cross-cutting HTTP processing:
    - Measures end-to-end request latency using high-resolution monotonic clocks.
    - Appends the X-Response-Time-Ms header to every HTTP response.

    Deliberately avoids database queries, JWT parsing, body decoding, or route-level
    authorization decisions, which belong in dependencies and route handlers.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start_time = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"
        return response
