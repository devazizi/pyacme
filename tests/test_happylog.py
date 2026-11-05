"""Tests for pyacmecli.happylog logging module covering R5."""

import logging
import os

import pytest

from pyacmecli.happylog import (
    LOG,
    ColorFormatter,
    remove_file_handlers,
    set_log_file,
    set_log_level,
    set_verbosity,
)


def test_color_formatter_does_not_mutate_record():
    """Verify R5: ColorFormatter does not mutate the original record.levelname in-place."""
    formatter = ColorFormatter(fmt="%(levelname)s %(message)s")
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Sample log message",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)

    # Formatted string should have ANSI escape codes
    assert "\033[36mINFO\033[0m" in formatted

    # BUT original record.levelname must NOT have been mutated!
    assert record.levelname == "INFO"
    assert "\033" not in record.levelname
    assert "\x1b" not in record.levelname


def test_color_formatter_all_colors():
    """Verify ANSI color codes for all supported levels."""
    formatter = ColorFormatter(fmt="%(levelname)s")
    for level, color in ColorFormatter.COLORS.items():
        rec = logging.LogRecord(
            name="test",
            level=getattr(logging, level),
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        res = formatter.format(rec)
        assert color in res


def test_file_logging_plain_text_without_ansi(tmp_path):
    """Verify set_log_file produces clean, structured plain text logs with no ANSI leaks."""
    log_file = tmp_path / "test.log"
    set_log_file(log_file)

    LOG.info("Hello info level")
    LOG.warning("Warning message")

    with open(str(log_file), "r", encoding="utf-8") as f:
        content = f.read()

    assert "INFO     [PYACME] Hello info level" in content
    assert "WARNING  [PYACME] Warning message" in content
    # Assert zero ANSI escape codes in file
    assert "\033" not in content
    assert "\x1b" not in content


def test_set_log_file_creates_nested_directories(tmp_path):
    """Verify set_log_file automatically creates missing parent directory paths."""
    nested_path = tmp_path / "logs" / "var" / "app.log"
    handler = set_log_file(nested_path)

    assert os.path.exists(str(nested_path))
    assert handler in LOG.handlers
    remove_file_handlers()
    assert handler not in LOG.handlers


def test_set_verbosity():
    """Verify set_verbosity switches between DEBUG and INFO."""
    set_verbosity(True)
    assert LOG.level == logging.DEBUG
    set_verbosity(False)
    assert LOG.level == logging.INFO


def test_set_log_level():
    """Verify set_log_level accepts strings and numbers, and raises ValueError on invalid."""
    set_log_level("WARNING")
    assert LOG.level == logging.WARNING

    set_log_level("error")
    assert LOG.level == logging.ERROR

    set_log_level(logging.CRITICAL)
    assert LOG.level == logging.CRITICAL

    with pytest.raises(ValueError, match="Invalid log level"):
        set_log_level("UNKNOWN_LEVEL")
