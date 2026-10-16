"""Sliding-window rate limiting per tool."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable
from fnmatch import fnmatchcase

from mcp_warden.policy import RateLimit


class RateLimiter:
    def __init__(self, limits: list[RateLimit], clock: Callable[[], float] = time.monotonic):
        self._limits = limits
        self._clock = clock
        self._hits: dict[tuple[int, str], deque[float]] = defaultdict(deque)

    def check(self, tool: str) -> str | None:
        """Record a call and return a reason string if any limit is exceeded."""
        now = self._clock()
        matched: list[tuple[int, RateLimit]] = [
            (i, lim) for i, lim in enumerate(self._limits) if fnmatchcase(tool, lim.tool)
        ]
        for i, lim in matched:
            # A wildcard limit is shared across tools; a named one is per tool.
            key = (i, "*" if lim.shared else tool)
            window = self._hits[key]
            while window and now - window[0] >= lim.per_seconds:
                window.popleft()
            if len(window) >= lim.max_calls:
                return (
                    f"rate limit exceeded: {lim.max_calls} call(s) per {lim.per_seconds:g}s "
                    f"for {lim.tool!r}"
                )
        for i, lim in matched:
            self._hits[(i, "*" if lim.shared else tool)].append(now)
        return None
