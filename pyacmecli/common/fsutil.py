"""Filesystem helpers: atomic writes, owner-only files and a process lock."""

import contextlib
import fcntl
import os
import tempfile
from collections.abc import Iterator

PRIVATE_FILE_MODE = 0o600
PUBLIC_FILE_MODE = 0o644


class LockBusyError(RuntimeError):
    """Raised when another pyacme process already holds the lock."""


def write_atomic(path: str, data: bytes | str, mode: int) -> None:
    """Replace path with data so readers see either the old or new content.

    The data goes to a temporary file in the same directory, is fsynced, and
    is then renamed over path. A crash or a full disk leaves the previous
    file intact instead of a truncated one that a web server could load.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        # mkstemp creates the file 0600; widen only when asked to.
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise


def write_private_file(path: str, data: bytes | str) -> None:
    """Atomically write data to path, readable by the owner only."""
    write_atomic(path, data, PRIVATE_FILE_MODE)


@contextlib.contextmanager
def exclusive_lock(lock_path: str) -> Iterator[None]:
    """Hold an exclusive, non-blocking flock on lock_path.

    The kernel releases the lock when the process exits, so a crashed run
    never leaves a stale lock behind.
    """
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusyError(
                f"Another pyacme process holds {lock_path}; try again later."
            ) from exc
        yield
    finally:
        os.close(fd)
