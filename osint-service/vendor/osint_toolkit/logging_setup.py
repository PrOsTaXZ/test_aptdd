"""Logging: rotating private log file with secret redaction.

Investigation targets are deliberately *not* logged by the engine; module code should log
module names and statuses, not personal identifiers.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from logging.handlers import RotatingFileHandler
from pathlib import Path

from osint_toolkit.config import Settings, ensure_private_dir

LOGGER_NAME = "osint_toolkit"
_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


class RedactingFilter(logging.Filter):
    """Replaces any known secret value in log records with ``[REDACTED]``."""

    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        self._secrets = sorted({s for s in secrets if len(s) >= 4}, key=len, reverse=True)

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._secrets:
            return True
        message = record.getMessage()
        redacted = message
        for secret in self._secrets:
            redacted = redacted.replace(secret, "[REDACTED]")
        if redacted != message:
            record.msg, record.args = redacted, None
        return True


class _PrivateRotatingFileHandler(RotatingFileHandler):
    """Rotating handler whose files are created with mode 0600."""

    def _open(self):  # type: ignore[no-untyped-def]
        path = Path(self.baseFilename)
        if not path.exists():
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
        path.chmod(0o600)
        return super()._open()


def setup_logging(settings: Settings, *, console_level: int | None = None) -> Path:
    """Configure the package logger. Returns the log file path."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    redactor = RedactingFilter(settings.secret_values())
    ensure_private_dir(settings.state_dir)
    log_file = ensure_private_dir(settings.log_dir) / "osint.log"

    file_handler = _PrivateRotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(settings.log_level)
    file_handler.setFormatter(logging.Formatter(_FORMAT))
    file_handler.addFilter(redactor)
    logger.addHandler(file_handler)

    if console_level is not None:
        from rich.logging import RichHandler

        console = RichHandler(show_path=False, rich_tracebacks=False, markup=False)
        console.setLevel(console_level)
        console.addFilter(redactor)
        logger.addHandler(console)
    return log_file
