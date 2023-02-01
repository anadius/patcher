import os
import shutil
import hashlib
import re
import tempfile
import subprocess

from pathlib import Path

from . import myzipfile
from .files import get_files_set

__all__ = ["PatchMaker", "get_files_set", "filter_files", "test_patterns"]

REPLACEMENTS = {
    "**/": "(?:.*?/)?",
    "**": ".*?",
    "*": "[^/]*",
    "?": "[^/]",
    "": "",
}


def _patterns_to_regexp(patterns):
    """
    Convert wildcard patterns into regular expression.
    """
    regexps = []
    for pattern in patterns:
        regexp = ""
        for match in re.finditer(r"(.*?)(\*\*/?|\*|\?|$)", pattern):
            regexp += re.escape(match.group(1))
            regexp += REPLACEMENTS[match.group(2)]
        regexps.append(regexp)

    return re.compile("^(?:{})$".format("|".join(regexps)))


def filter_files(files_set, patterns):
    """
    Create a new set of files that match the pattern.
    """
    if patterns is None:
        return set()
    regexp = _patterns_to_regexp(patterns)
    return {file for file in files_set if regexp.match(file)}


def test_patterns(folder_path_or_files_set, patterns):
    """
    Helper function for testing patterns.
    If you're going to call this function multiple times with the same folder
    use `get_files_set` first and pass the files set instead of the folder path.
    """
    if isinstance(folder_path_or_files_set, set):
        files_set = folder_path_or_files_set
    else:
        files_set = get_files_set(folder_path_or_files_set)
    files_set = filter_files(files_set, patterns)
    return "\n".join(sorted(files_set))


def _ensure_deleted(file_path):
    try:
        os.unlink(file_path)
    except FileNotFoundError:
        pass


def _default_callback(callback_type, *args):
    """
    Default callback, just prints whatever you pass to it.
    """
    print(callback_type, *args)


class PatchMaker:
    VERSION = 1

    def __init__(self, game_name, callback=None):
        self.game_name = game_name
        self.callback = _default_callback if callback is None else callback

    def _hash_file(self, path):
        self.callback("hashing", str(path))
        m = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                buf = f.read(65536)
                if not buf:
                    break
                m.update(buf)
        return m.hexdigest().upper()

    def _add_hash(self, posix_rel_path, path, hashes, other_hashes=None):
        """
        Add MD5 hash to `hashes` dict if missing. Try to get it from `other_hashes`
        first and if that fails - calculate it.
        """
        if posix_rel_path not in hashes:
            try:
                hashes[posix_rel_path] = other_hashes[posix_rel_path]
            except (KeyError, TypeError):
                hashes[posix_rel_path] = self._hash_file(path)

    def _pack(
        self,
        metadata,
        files_dict,
        output_path,
        hashes=None,
        store=None,
        exists=False,
    ):
        if hashes is None:
            hashes = {}
        if store is None:
            store = set()

        metadata["game_name"] = self.game_name
        metadata["patcher_version"] = self.VERSION
        metadata["files"] = {}

        with myzipfile.ZipFile(
            output_path,
            "a" if exists else "w",
            compression=myzipfile.ZIP_DEFLATED,
            compresslevel=9,
            # compression=myzipfile.ZIP_LZMA,
            # compresslevel={"dict_size": 67108864},
            store_if_smaller=True,
        ) as zf:
            if exists:
                compressed_sizes = {}
                filelist = zf.filelist[::]
                filelist.sort(key=lambda x: x.header_offset)
                for i in range(len(filelist)):
                    try:
                        end = filelist[i + 1].header_offset
                    except IndexError:
                        end = zf.start_dir
                    zinfo = filelist[i]
                    compressed_sizes[zinfo.filename] = end - zinfo.header_offset

            for posix_rel_path in sorted(files_dict.keys()):
                path = files_dict[posix_rel_path]
                self._add_hash(posix_rel_path, path, hashes)

                if not exists:
                    self.callback("compressing", posix_rel_path)

                    if posix_rel_path in store:
                        zf.write(path, posix_rel_path, compress_type=myzipfile.ZIP_STORED)
                    else:
                        zf.write(path, posix_rel_path)

                zinfo = zf.getinfo(posix_rel_path)
                if not exists:
                    compressed_size = zf.start_dir - zinfo.header_offset
                else:
                    compressed_size = compressed_sizes[posix_rel_path]

                metadata["files"][posix_rel_path] = {
                    "offset": zinfo.header_offset,
                    "size": zinfo.file_size,
                    "compressed_size": compressed_size,
                    "MD5": hashes[posix_rel_path],
                }

            zf.write_metadata(metadata)

        return metadata

    def _simple_pack(
        self,
        metadata,
        folder_or_iterable_of_files,
        *args,
        include_files=None,
        exclude_files=None,
        **kwargs,
    ):
        try:
            folder = Path(folder_or_iterable_of_files)
        except TypeError:
            folder = Path(".")
            files = set(folder_or_iterable_of_files)
        else:
            files = get_files_set(folder)

        if include_files is not None:
            files = filter_files(files, include_files)

        files -= filter_files(files, exclude_files)

        files_dict = {file: folder / file for file in sorted(files)}

        return self._pack(metadata, files_dict, *args, **kwargs)

    def pack_base_files(self, *args, **kwargs):
        """
        pack_base_files(
            folder_or_iterable_of_files,
            output_path,
            include_files=None,
            exclude_files=None,
            hashes=None,
            store=None,
            exists=False,
        )
        """
        return self._simple_pack({"type": "base"}, *args, **kwargs)

    def pack_extra(self, *args, **kwargs):
        return self._simple_pack({"type": "extra"}, *args, **kwargs)

    def pack_full_patch(self, version, *args, **kwargs):
        return self._simple_pack(
            {"type": "full_patch", "version": version}, *args, **kwargs
        )

    def pack_dlc(self, name, *args, **kwargs):
        return self._simple_pack({"type": "dlc", "name": name}, *args, **kwargs)

    def _ensure_safe_path(self, path, safe_path):
        try:
            str(path).encode("ascii")
        except UnicodeError:
            pass
        else:
            return path

        try:
            os.link(path, safe_path)
        except OSError:
            pass
        else:
            self.callback("hardlinked", str(path), str(safe_path))
            return safe_path

        self.callback("copying", str(path), str(safe_path))
        shutil.copy2(path, safe_path)
        return safe_path

    def make_patch(
        self,
        output_path,
        version_from,
        version_to,
        folder_from,
        folder_to,
        extension,
        crack_path=None,
        crack_password=None,
        crack_hash=None,
        hashes_from=None,
        hashes_to=None,
        include_files=None,
        exclude_files=None,
        always_new=None,
        language_files=None,
        optional_files=None,
    ):

        # Make sure we have Path objects.
        folder_from = Path(folder_from)
        folder_to = Path(folder_to)

        if hashes_from is None:
            hashes_from = {}
        if hashes_to is None:
            hashes_to = {}
        if language_files is None:
            language_files = {}

        # Ensure extension starts with a dot.
        if not extension.startswith("."):
            extension = f".{extension}"

        metadata = {
            "type": "patch",
            "version": version_to.strip(),
            "version_from": version_from.strip(),
            "extension": extension,
        }

        if crack_path is not None:
            crack_path = Path(crack_path)
            metadata["crack"] = {
                "filename": crack_path.name,
                "hash": crack_hash or self._hash_file(crack_path),
                "pass": None if crack_password == "" else crack_password,
            }

        # Get files from the old and the new folder.
        files_from = get_files_set(folder_from)
        files_to = get_files_set(folder_to)
        if include_files is not None:
            files_from = filter_files(files_from, include_files)
            files_to = filter_files(files_to, include_files)

        # Filter out excluded files.
        files_from -= filter_files(files_from, exclude_files)
        files_to -= filter_files(files_to, exclude_files)

        deleted = files_from - files_to

        # By removing files from the old files set they are always treated as new.
        files_from -= (filter_files(files_from, always_new) - deleted)

        # Add a dict with the language files.
        metadata["languages"] = {
            lang: list(sorted(filter_files(files_to, patterns)))
            for lang, patterns in language_files.items()
        }

        # Add a list with the optional files.
        metadata["optional"] = list(sorted(filter_files(files_to, optional_files)))

        # Add a list with the deleted files.
        metadata["deleted"] = list(sorted(deleted))

        files_new = files_to - files_from
        # Add a list with the new files.
        metadata["new"] = list(sorted(files_new))

        # Dicts with hashes and the actual file paths that will be passed
        # to `self._pack`. Both use relative posix paths as keys.
        hashes = {}
        files_dict = {}
        store = set()

        # Process new files.
        for file in sorted(files_new):
            path = folder_to / file
            self._add_hash(file, path, hashes, hashes_to)
            files_dict[file] = path

        # Process common files.
        with tempfile.TemporaryDirectory(dir=".") as tmp:
            temp = Path(tmp)
            safe_from = temp / "from"
            safe_to = temp / "to"
            safe_xdelta = temp / "xdelta"

            patches = {}
            for file in sorted(files_from & files_to):
                path_from = folder_from / file
                path_to = folder_to / file
                file_xdelta = file + extension
                path_xdelta = temp / file_xdelta

                # Calculate hashes if missing.
                self._add_hash(file, path_from, hashes_from)
                self._add_hash(file, path_to, hashes_to)

                if hashes_from[file].upper() != hashes_to[file].upper():
                    # xdelta3 on Windows doesn't like Unicode paths, ensure ASCII.
                    path_old = self._ensure_safe_path(path_from, safe_from)
                    path_new = self._ensure_safe_path(path_to, safe_to)
                    path_xdelta.parent.mkdir(parents=True, exist_ok=True)

                    patches[file] = {
                        "MD5_from": hashes_from[file],
                        "size_from": os.path.getsize(path_from),
                        "MD5_to": hashes_to[file],
                        "size_to": os.path.getsize(path_to),
                    }

                    self.callback("xdelta", file_xdelta)
                    p = subprocess.Popen(
                        [
                            "xdelta3",
                            "-A",
                            "-B2147483648",
                            "-e",
                            "-s",
                            str(path_old),
                            str(path_new),
                            str(safe_xdelta),
                        ]
                    )
                    while True:
                        try:
                            p.wait(0.1)
                        except subprocess.TimeoutExpired:
                            pass
                        except KeyboardInterrupt:
                            p.terminate()
                            raise
                        else:
                            break

                    if p.returncode != 0:
                        raise subprocess.CalledProcessError(p.returncode, p.args)

                    safe_xdelta.rename(path_xdelta)
                    files_dict[file_xdelta] = path_xdelta
                    store.add(file_xdelta)

                _ensure_deleted(safe_from)
                _ensure_deleted(safe_to)

            metadata["patches"] = patches

            final_metadata = self._pack(
                metadata, files_dict, output_path, hashes, store
            )
        return final_metadata

"""
if __name__ == "__main__":
    p = PatchMaker("The Sims 4")
    p.pack_dlc(
        "[FP01] Holiday Celebration Pack",
        r"C:\Games\The Sims 4",
        r"F:\GitHub\patcher\Sims4_DLC_FP01_Holiday_Celebration_Pack.zip",
        include_files=["FP01/**", "__Installer/DLC/FP01/**"],
        exclude_files=["**/*Log.txt"],
    )
    p.pack_dlc(
        "[GP01] Outdoor Retreat",
        r"C:\Games\The Sims 4",
        r"F:\GitHub\patcher\Sims4_DLC_GP01_Outdoor_Retreat.zip",
        include_files=["GP01/**", "__Installer/DLC/GP01/**"],
        exclude_files=["**/*Log.txt"],
    )
"""
