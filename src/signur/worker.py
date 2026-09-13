import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from signur.config import get_settings
from signur.database import SessionLocal
from signur.signature_service import (
    claim_next_signature,
    process_claimed_signature,
    release_orphaned_signatures,
)
from signur.work_signal import work_signal

logger = logging.getLogger(__name__)


def run_once() -> bool:
    settings = get_settings()
    with SessionLocal() as session:
        job_id = claim_next_signature(session)
    if job_id is None:
        return False
    with SessionLocal() as session:
        completed = process_claimed_signature(session, settings, job_id)
    if completed:
        logger.info("Signature job completed", extra={"signature_job_id": str(job_id)})
    else:
        logger.warning("Signature job failed", extra={"signature_job_id": str(job_id)})
    return True


def _release_orphans() -> int:
    with SessionLocal() as session:
        return release_orphaned_signatures(session)


async def _pump(poll_seconds: float) -> None:
    """Work off the queue without blocking the event loop."""
    work_signal.listen()
    try:
        released = await asyncio.to_thread(_release_orphans)
    except Exception:  # the queue must be worked off even if the sweep fails
        logger.exception("Could not close the interrupted signature attempts")
    else:
        if released:
            logger.warning(
                "Signature attempts interrupted by a previous run were closed",
                extra={"released": released},
            )
    while True:
        try:
            busy = await asyncio.to_thread(run_once)
        except Exception:  # a failed job must never stop the pump
            logger.exception("Signature job raised")
            busy = False
        if not busy:
            # Whoever queues a signature says so; the interval is only the
            # sweep that catches a nudge nobody sent.
            await work_signal.wait(poll_seconds)


@asynccontextmanager
async def running_worker(poll_seconds: float) -> AsyncIterator[None]:
    """Run the signature worker for as long as the service is up."""
    task = asyncio.create_task(_pump(poll_seconds))
    logger.info("Signur signature worker started")
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        work_signal.stop_listening()
        logger.info("Signur signature worker stopped")
