"""Filesystem helpers for files that hold secret material."""

import os

PRIVATE_FILE_MODE = 0o600


def write_private_file(path: str, data: bytes | str) -> None:
    """Write data to path readable and writable by the owner only.

    The mode is passed at creation so the file is never world-readable, and
    re-applied with chmod because an already existing file keeps its old mode.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    with os.fdopen(fd, "wb") as f:
        os.chmod(path, PRIVATE_FILE_MODE)
        f.write(data)
