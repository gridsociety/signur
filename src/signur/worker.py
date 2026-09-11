import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from signur.config import get_settings
from signur.database import SessionLocal
from signur.signature_service import claim_next_signature, process_claimed_signature

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


async def _pump(poll_seconds: float) -> None:
    """Work off the queue without blocking the event loop."""
    while True:
        try:
            busy = await asyncio.to_thread(run_once)
        except Exception:  # a failed job must never stop the pump
            logger.exception("Signature job raised")
            busy = False
        if not busy:
            await asyncio.sleep(poll_seconds)


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
        logger.info("Signur signature worker stopped")
