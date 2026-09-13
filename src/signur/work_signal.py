"""The nudge that tells the worker a signature is waiting.

The worker lives in the server process, so it does not have to ask the database
every second whether anything arrived: whoever queues a signature says so. The
wait still ends on its own after a while, because a sweep of the queue is the
safety net for a nudge that never came.
"""

import asyncio
import contextlib
import threading


class WorkSignal:
    def __init__(self) -> None:
        # Requests are served in their own threads; the worker waits in the loop.
        self._guard = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._event: asyncio.Event | None = None
        self._missed = False

    def listen(self) -> None:
        """Take up position: called by the worker, inside its own event loop."""
        with self._guard:
            self._loop = asyncio.get_running_loop()
            self._event = asyncio.Event()
            if self._missed:
                # Something was queued before the worker was ready for it.
                self._missed = False
                self._event.set()

    def stop_listening(self) -> None:
        with self._guard:
            self._loop = None
            self._event = None

    def notify(self) -> None:
        """Say there is work. Safe to call from any thread, and never fails."""
        with self._guard:
            loop, event = self._loop, self._event
            if loop is None or event is None:
                self._missed = True
                return
        with contextlib.suppress(RuntimeError):  # the loop is already closing
            loop.call_soon_threadsafe(event.set)

    async def wait(self, timeout: float) -> None:
        """Wait for a nudge, or for the sweep to come round anyway."""
        event = self._event
        if event is None:
            await asyncio.sleep(timeout)
            return
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(event.wait(), timeout)
        # Cleared after waking, never before: a nudge that lands while the
        # worker is signing must still be there when it comes back to wait.
        event.clear()


work_signal = WorkSignal()
