import os

from tempfile import gettempdir
from pathlib import Path

__all__ = ["is_in_temp", "is_in_system"]


def is_in_temp():
    temp = Path(gettempdir()).resolve()
    cwd = Path(".").resolve()
    try:
        cwd.relative_to(temp)
    except ValueError:
        return False
    return True

def is_in_system():
    if os.name == "nt":
        cwd = Path(".").resolve()
        try:
            cwd.relative_to(os.environ.get("SystemRoot"))
        except (ValueError, TypeError):
            return False
        return True
    return False