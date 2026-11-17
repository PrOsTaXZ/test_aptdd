"""Minimum-interval rate limiter shared by all modules of one investigation."""

from __future__ import annotations

import asyncio


class RateLimiter:
    """Guarantees at least ``min_interval`` seconds between the starts of acquisitions."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = max(0.0, min_interval)
        self._lock = asyncio.Lock()
        self._last: float | None = None

    async def wait(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            if self._last is not None:
                delay = self._last + self.min_interval - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
            self._last = loop.time()
