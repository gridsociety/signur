import logging
import time

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


def run() -> None:
    settings = get_settings()
    settings.validate_security()
    logging.basicConfig(level=logging.INFO)
    logger.info("Signur signature worker started")
    try:
        while True:
            if not run_once():
                time.sleep(settings.worker_poll_seconds)
    except KeyboardInterrupt:
        logger.info("Signur signature worker stopped")


if __name__ == "__main__":
    run()
