"""Sliding-window rate limiting per tool (or server request), optionally per client."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable
from fnmatch import fnmatchcase

from mcp_warden.policy import RateLimit

# How many checks pass between sweeps of windows that have gone quiet.
SWEEP_EVERY = 1024

Key = tuple[int, "str | None", str]


class RateLimiter:
    def __init__(self, limits: list[RateLimit], clock: Callable[[], float] = time.monotonic):
        self._limits = limits
        self._clock = clock
        self._hits: dict[Key, deque[float]] = defaultdict(deque)
        self._checks = 0

    def _key(self, i: int, lim: RateLimit, name: str, client: str | None) -> Key:
        # A wildcard limit is shared across names; a named one is per name. A per-client
        # limit keeps one such budget for each client.
        return (i, client if lim.per_client else None, "*" if lim.shared else name)

    def check(self, name: str, client: str | None = None) -> str | None:
        """Record a call and return a reason string if any limit is exceeded."""
        now = self._clock()
        self._checks += 1
        if self._checks % SWEEP_EVERY == 0:
            self._sweep(now)
        matched = [(i, lim) for i, lim in enumerate(self._limits) if fnmatchcase(name, lim.tool)]
        for i, lim in matched:
            window = self._hits[self._key(i, lim, name, client)]
            while window and now - window[0] >= lim.per_seconds:
                window.popleft()
            if len(window) >= lim.max_calls:
                scope = " for this client" if lim.per_client and client is not None else ""
                return (
                    f"rate limit exceeded: {lim.max_calls} call(s) per {lim.per_seconds:g}s "
                    f"for {lim.tool!r}{scope}"
                )
        for i, lim in matched:
            self._hits[self._key(i, lim, name, client)].append(now)
        return None

    def _sweep(self, now: float) -> None:
        """Forget windows with no hit inside their limit's period (e.g. ended sessions)."""
        for key in [
            k
            for k, window in self._hits.items()
            if not window or now - window[-1] >= self._limits[k[0]].per_seconds
        ]:
            del self._hits[key]
