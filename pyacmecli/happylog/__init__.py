"""Colored console logger for pyacme CLI."""

import logging
import sys


class ColorFormatter(logging.Formatter):
    """Formatter that colorizes level names on supported terminals."""

    COLORS = {
        "DEBUG": "\033[37m",  # White
        "INFO": "\033[36m",  # Cyan
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[41m",  # Red background
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[levelname]}{levelname}{self.RESET}"
            )
        return super().format(record)


def setup_custom_logger(name: str) -> logging.Logger:
    """Create and return a logger with colored stdout handler."""
    formatter = ColorFormatter(
        fmt="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    screen_handler.setLevel(
        logging.DEBUG
    )  # handler shows all; logger level filters

    logger = logging.getLogger(name)
    logger.setLevel(
        logging.INFO
    )  # default: INFO and above; use set_verbosity to change
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(screen_handler)
    return logger


LOG = setup_custom_logger("PYACME")


LEVEL_NAMES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def set_verbosity(verbose: bool) -> None:
    """Set log level from CLI --verbose flag: True = DEBUG, False = INFO."""
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)


def set_log_level(level: str | int) -> None:
    """Set log level by name (DEBUG, INFO, WARNING, ERROR, CRITICAL) or numeric level."""
    if isinstance(level, str):
        level = level.upper()
        if level not in LEVEL_NAMES:
            raise ValueError(
                f"Invalid log level {level!r}; choose from {LEVEL_NAMES}"
            )
        level = getattr(logging, level)
    LOG.setLevel(level)


__all__ = ["LOG", "set_verbosity", "set_log_level", "LEVEL_NAMES"]
