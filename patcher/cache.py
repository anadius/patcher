import os
import errno
import json

from pathlib import Path

from .exceptions import PatcherError, NotEnoughSpaceError

__all__ = ["load", "save"]


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (
        FileNotFoundError, # obvious
        json.JSONDecodeError, # corrupted file
        UnicodeDecodeError, # also corrupted file, should be ascii
    ):
        return None
    except (OSError, PermissionError):
        raise PatcherError(
            f'Can\'t read "{path}". Make sure your '
            "anti-virus doesn't block this program."
        )


def save(path, obj):
    try:
        serialized = json.dumps(obj)
    except TypeError:
        return

    path = str(path)
    path_tmp = f"{path}_tmp"
    try:
        with open(path_tmp, "w") as f:
            f.write(serialized)
        os.replace(path_tmp, path)
    except (OSError, PermissionError) as e:
        if e.errno == errno.ENOSPC:
            raise NotEnoughSpaceError(
                f"You don't have enough space on {Path(path).anchor} drive!"
            )
        raise PatcherError(
            f'Can\'t save "{path}". Make sure your '
            "anti-virus doesn't block this program. "
            "If this file exists - move it somewhere else and then copy "
            "it back. If it doesn't exist - do the same with the folder "
            "this file was supposed to be in."
        )
