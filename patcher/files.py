import os
import shutil
import hashlib

from pathlib import Path

from .exceptions import WritePermissionError, NotEnoughSpaceError

__all__ = [
    "get_short_path",
    "write_check",
    "get_files_dict",
    "get_files_set",
    "hash_file",
    "copyfileobj",
    "delete_empty_dirs",
]


if os.name == "nt":
    import pywintypes
    import win32file
    import win32timezone

    def get_short_path(long_path):
        path = Path(long_path)
        final_path = None
        for part in path.parts:
            try:
                part.encode("ascii")
            except UnicodeEncodeError:
                try:
                    safe_part = win32file.FindFilesW(os.path.join(final_path, part))[0][9]
                    if safe_part == "" or safe_part is None:
                        return None
                except (
                    IndexError,
                    pywintypes.error,
                ):
                    return None
            else:
                safe_part = part

            if final_path is not None:
                final_path = os.path.join(final_path, safe_part)
            else:
                final_path = safe_part

        return final_path

else:

    def get_short_path(long_path):
        return long_path


def write_check(path="."):
    if path == ".":
        text = (
            "this folder.\nDo NOT put this program directly on your "
            "system drive (C:) nor in Program Files!"
        )
    else:
        text = f'"{path}". Try copying your game somewhere else.'
    path = Path(path)

    i = 0
    while True:
        file_path = path / f"tmp_file_{i}"
        try:
            path.mkdir(parents=True, exist_ok=True)
            with open(file_path, "x"):
                pass
            file_path.unlink()
        except FileExistsError:
            i += 1
            continue
        except (PermissionError, FileNotFoundError, OSError):
            raise WritePermissionError(
                f"Write test failed. Cannot create files in {text}"
            )
        else:
            break


def get_files_dict(folder_path, all_folders=None):
    """
    Get a dict of files from specified folder. Values are `os.DirEntry.stat` method.

    On Unix, this method always requires a system call. On Windows, it only
    requires a system call if `follow_symlinks` is `True` and the entry is
    a reparse point (for example, a symbolic link or directory junction).
    """
    result = {}

    if not os.path.isdir(folder_path):
        return result

    paths = [folder_path]
    while len(paths) > 0:
        path = paths.pop(0)
        rel_path = Path(path).relative_to(folder_path).as_posix()
        try:
            with os.scandir(path) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        if rel_path != ".":
                            p = rel_path + "/" + entry.name
                        else:
                            p = entry.name
                        result[p] = entry.stat
                    elif entry.is_dir(follow_symlinks=False):
                        paths.append(entry.path)
        except (PermissionError, OSError):
            if all_folders is not None and rel_path not in all_folders:
                continue

            raise WritePermissionError(
                f'Can\'t read files from "{path}". '
                "Try copying it somewhere else."
            )

    return result


def get_files_set(folder_path):
    """
    Get a set of files from specified folder.
    """
    return set(get_files_dict(folder_path).keys())


def hash_file(path, chunk_size=65536, progress=None):
    processed = 0

    if progress is not None:
        progress(processed)

    m = hashlib.md5()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            m.update(chunk)

            processed += len(chunk)
            if progress is not None:
                progress(processed)
    return m.hexdigest().upper()


def copyfileobj(fsrc, fdst, progress, length=0):
    """copy data from file-like object fsrc to file-like object fdst"""
    # Localize variable access to minimize overhead.
    if not length:
        length = shutil.COPY_BUFSIZE
    copied = 0
    progress(copied)
    fsrc_read = fsrc.read
    fdst_write = fdst.write
    while buf := fsrc_read(length):
        fdst_write(buf)
        copied += len(buf)
        progress(copied)


def delete_empty_dirs(src_dir):
    for dirpath, _, _ in os.walk(src_dir, topdown=False):
        try:
            os.rmdir(dirpath)
        except OSError:
            pass
