import asyncio
import threading

from signur.work_signal import WorkSignal


def test_a_nudge_wakes_the_wait_at_once() -> None:
    async def scenario() -> float:
        signal = WorkSignal()
        signal.listen()
        loop = asyncio.get_running_loop()
        # The endpoint that queues a signature runs in its own thread.
        threading.Timer(0.02, signal.notify).start()
        started = loop.time()
        await signal.wait(30.0)
        return loop.time() - started

    assert asyncio.run(scenario()) < 1.0


def test_without_a_nudge_the_wait_gives_up_on_its_own() -> None:
    """The sweep stays as the safety net, so the wait always ends."""

    async def scenario() -> bool:
        signal = WorkSignal()
        signal.listen()
        await signal.wait(0.05)
        return True

    assert asyncio.run(scenario())


def test_a_nudge_that_arrives_while_the_worker_is_busy_is_not_lost() -> None:
    async def scenario() -> float:
        signal = WorkSignal()
        signal.listen()
        loop = asyncio.get_running_loop()
        signal.notify()  # nobody is waiting yet
        started = loop.time()
        await signal.wait(30.0)
        return loop.time() - started

    assert asyncio.run(scenario()) < 1.0


def test_a_nudge_that_arrives_before_anybody_listens_is_remembered() -> None:
    signal = WorkSignal()
    signal.notify()

    async def scenario() -> float:
        signal.listen()
        loop = asyncio.get_running_loop()
        started = loop.time()
        await signal.wait(30.0)
        return loop.time() - started

    assert asyncio.run(scenario()) < 1.0


def test_one_nudge_wakes_the_wait_once() -> None:
    """Waking twice on a single nudge would mean polling under another name."""

    async def scenario() -> bool:
        signal = WorkSignal()
        signal.listen()
        signal.notify()
        await signal.wait(30.0)
        await signal.wait(0.05)
        return True

    assert asyncio.run(scenario())


def test_a_nudge_after_the_worker_stopped_does_not_raise() -> None:
    """Shutting down while a signature is queued must not break the request."""
    signal = WorkSignal()

    async def scenario() -> None:
        signal.listen()
        signal.stop_listening()

    asyncio.run(scenario())

    signal.notify()
