import logging
import sys

formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S')


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[37m",  # White
        "INFO": "\033[36m",  # Cyan
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[41m",  # Red background
    }
    RESET = "\033[0m"

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)


def setup_custom_logger(name):
    formatter = ColorFormatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                               datefmt='%Y-%m-%d %H:%M:%S')

    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(screen_handler)

    return logger


LOG = setup_custom_logger('PYACME')


__init__ = [LOG]
