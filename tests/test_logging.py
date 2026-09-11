import logging

import pytest

from signur.main import configure_logging


def detached(name: str) -> logging.Logger:
    """Build a logger outside the global registry, so tests cannot leak."""
    return logging.Logger(name)


def test_worker_lines_reach_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    logger = detached("signur.worker")
    configure_logging(logger)
    logger.info("Signature job completed")
    error = capsys.readouterr().err
    assert "Signature job completed" in error
    assert "INFO" in error
    assert "signur.worker" in error


def test_configuring_twice_does_not_duplicate_the_output() -> None:
    logger = detached("signur")
    configure_logging(logger)
    configure_logging(logger)
    assert len(logger.handlers) == 1


def test_an_existing_setup_wins() -> None:
    logger = detached("signur")
    existing = logging.StreamHandler()
    logger.addHandler(existing)
    configure_logging(logger)
    assert logger.handlers == [existing]
