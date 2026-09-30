# Provides a single configured logger that writes both to the console and to a file-based execution log for audit cross-referencing

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def get_logger(name: str = "tdve", log_file: str | None = None,
               verbose: bool = False) -> logging.Logger:
    """Return a logger configured for console + optional file output.

    Idempotent: repeated calls with the same name will not stack handlers.
    """
    logger = logging.getLogger(name)
    if getattr(logger, "_tdve_configured", False):
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console = logging.StreamHandler(stream=sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # full detail on disk
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger._tdve_configured = True  # type: ignore[attr-defined]
    return logger
