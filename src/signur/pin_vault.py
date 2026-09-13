"""The PIN typed for a single signature, kept in memory and never written down.

The worker that signs runs inside the server process, so a PIN meant for one
signature has no reason to reach the database: it waits here until the worker
asks for it, and is handed over exactly once. A PIN nobody collects is
forgotten after a while, and a restart takes every one of them with it, which
is the point: what is not stored cannot be read later.
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

FORGET_AFTER_SECONDS = 30 * 60.0


@dataclass(frozen=True)
class _Held:
    pin: str
    forget_at: float


class PinVault:
    def __init__(
        self,
        forget_after_seconds: float = FORGET_AFTER_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._forget_after_seconds = forget_after_seconds
        self._clock = clock
        # The worker signs in its own thread while requests keep arriving.
        self._lock = threading.Lock()
        self._held: dict[str, _Held] = {}

    def _forget_stale(self, now: float) -> None:
        for key in [key for key, held in self._held.items() if held.forget_at <= now]:
            del self._held[key]

    def hold(self, job_id: object, pin: str) -> None:
        """Keep ``pin`` until the worker claims the job it belongs to."""
        now = self._clock()
        with self._lock:
            self._forget_stale(now)
            self._held[str(job_id)] = _Held(pin, now + self._forget_after_seconds)

    def take(self, job_id: object) -> str | None:
        """Hand the PIN over, once: whoever asks second gets nothing."""
        now = self._clock()
        with self._lock:
            self._forget_stale(now)
            held = self._held.pop(str(job_id), None)
        return held.pin if held is not None else None

    def discard(self, job_id: object) -> None:
        with self._lock:
            self._held.pop(str(job_id), None)

    def held_count(self) -> int:
        with self._lock:
            return len(self._held)


pin_vault = PinVault()
