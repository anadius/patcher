import sys
import json
import os
import io
import shutil
import re
import tempfile
import subprocess
import time
import errno
import zlib

from pathlib import Path
from enum import Enum
from threading import Event

from . import myzipfile
from . import cache
from .subprocess_ import Popen2
from .exceptions import *
from .files import *
from .utils import *

__all__ = ["Patcher", "ExitingError"]

CallbackType = Enum(
    "CallbackType",
    (
        "HEADER",
        "INFO",
        "FAILURE",
        "FINISHED",
        "PROGRESS",
        "WARNING",
    ),
)

LAST_STEP_ERROR = (
    'Can\'t {action} "{path}". Disable your anti-virus and try again. If your game'
    ' is in "Program Files" or "Program Files (x86)" move it somewhere else, for'
    ' example "C:\Games\The Sims 4". If you still get this error - reset file'
    " permissions - see the FAQ in the readme file. And if that still doesn't help"
    ' - copy files from "{final}" and "{crack}" to "{game}" and replace the files.'
)

UNRAR_ERRORS = {
    # 0 - success
    1: "",
    # 2 - fatal error - I want to see what it says
    3: "CRC error. ",
    4: "Lock error. ",
    5: "Write error. ",
    6: "Open error. ",
    # 7 - user error - I want to see what it says
    8: "Memory error. ",
    9: "Create error. ",
    # 10 - file missing, add path to message
    # 11 - bad password, add path and password to message
    12: "Read error. ",
    # 255 - user break error - I want to see what it says
}


def filter_metadata(metadata_list, type_):
    filtered_metadata = []
    for x in list(metadata_list):
        if x.get("type") == type_:
            filtered_metadata.append(x)
            metadata_list.remove(x)

    return filtered_metadata


def _parse_patches(metadata_list):
    patches = [metadata_list.pop(0)]

    while len(metadata_list) > 0:
        found = False
        version = patches[-1].get("version")
        for metadata in metadata_list:
            if version == metadata.get("version_from"):
                found = True
                break
        if found:
            patches.append(metadata)
            metadata_list.remove(metadata)
            continue
        break

    while len(metadata_list) > 0:
        found = False
        version = patches[0].get("version_from")
        for metadata in metadata_list:
            if version == metadata.get("version"):
                found = True
                break
        if found:
            patches.insert(0, metadata)
            metadata_list.remove(metadata)
            continue
        break

    return (patches[0].get("version_from"), patches[-1].get("version")), patches


def parse_patches(metadata_list, crack_missing_fatal=True):
    unparsed_patches = filter_metadata(metadata_list, "patch")
    sorted_patches = None
    all_versions = []

    while len(unparsed_patches) > 0:
        versions, sorted_patches = _parse_patches(unparsed_patches)
        all_versions.append(versions)

    if len(all_versions) > 1:
        versions_text = ""
        for v_from, v_to in all_versions:
            versions_text += f"\n{v_from} -> {v_to}"

        raise VersionsMissingError(
            "Some patches are missing or duplicated, available patches:"
            f"{versions_text}"
        )

    if sorted_patches is None:
        return None, {
            "full": {},
            "delta": {},
            "crack": None,
            "languages": {},
            "optional": [],
            "deleted": [],
        }

    full = {}
    delta = {}
    deleted = set()

    for patch in sorted_patches:
        deleted |= set(patch["deleted"])
        deleted -= set(patch["new"])
        for file in deleted:
            full.pop(file, None)
            delta.pop(file, None)

        extra = patch["extra"]

        for file in patch["new"]:
            delta.pop(file, None)  # faster than catching exception
            info = {}
            info.update(patch["files"][file])
            info.update(extra)
            full[file] = info

        ext = patch["extension"]
        for file, patch_info in patch["patches"].items():
            info = {"extension": ext}
            info.update(patch["files"][file + ext])
            info.update(patch_info)
            info.update(extra)

            if file in delta:
                if delta[file][-1]["MD5_to"] != info["MD5_from"]:
                    raise ContinuityError(
                        (
                            f'Patch for "{file}" from version '
                            f"{patch['version_from']} to {patch['version']} "
                            "can't be combined with the previous patch for that file."
                        ),
                        file,
                        patch["version_from"],
                        patch["version"],
                    )
                delta[file].append(info)
            else:
                delta[file] = [info]

    patches = {
        "full": full,
        "delta": delta,
        "crack": sorted_patches[-1].get("crack"),  # the only optional key
        "languages": sorted_patches[-1]["languages"],
        "optional": sorted_patches[-1]["optional"],
        "deleted": list(sorted(deleted)),
    }

    crack = patches["crack"]
    if crack is not None:
        filename = crack["filename"]
        if crack_missing_fatal and not Path(filename).is_file():
            raise CrackMissingError(
                f"Crack ({filename}) not found!",
                filename,
            )

    return versions, patches


def _should_replace(file, file_in_metadata, file_in_other, extra_in_other):
    return True


def parse_other(metadata, other, should_replace=_should_replace):
    extra = other["extra"]
    extra["type"] = other["type"]

    for file in other["files"].keys():
        o = other["files"][file]

        # this shouldn't happen in the Patcher, it will in my Sims 4 Updater though
        if file in metadata["full"]:
            m = metadata["full"][file]
            if o["MD5"] != m["MD5"]:
                # Something in "full" but not in "delta" - that means stuff in "full"
                # is the newest one, so don't replace it.
                if file not in metadata["delta"]:
                    continue

                no_patch = True
                for patch in metadata["delta"][file]:
                    if o["MD5"] == patch["MD5_to"]:
                        no_patch = False
                        break
                if no_patch:
                    continue
            elif not should_replace(file, m, o, extra):
                continue
        elif file in metadata["deleted"]:
            continue

        info = {}
        info.update(o)
        info.update(extra)

        metadata["full"][file] = info


def get_hashes_and_sizes(metadata):
    files_info = {}

    f = metadata["full"]
    d = metadata["delta"]
    full = set(f.keys())
    delta = set(d.keys())

    for file in full - delta:
        i = f[file]
        files_info[file] = (i["MD5"], i["size"])

    # The newest delta is always the newest file.
    for file in delta:
        i = d[file][-1]
        files_info[file] = (i["MD5_to"], i["size_to"])

    return files_info


def get_all_delta(metadata):
    all_delta = {}
    for file, deltas in metadata["delta"].items():
        for delta in deltas:
            all_delta[file + delta["extension"]] = delta
    return all_delta


def check_for_full_file(file, metadata, files_info):
    if file not in metadata["full"]:
        if file in metadata["optional"]:
            del files_info[file]
            
        else:
            raise CannotUpdateError(
                f"\"{file}\" can't be updated! You didn't download all "
                "required patches or your game installation is corrupted."
            )


def _default_callback(callback_type, *args):
    """
    Default callback, just prints whatever you pass to it.
    """
    print(callback_type, *args)


class Patcher:
    VERSION = 1
    NAME = "Patcher"

    def __init__(self, ask_question, callback=None):
        self.ask_question = ask_question
        self.callback = _default_callback if callback is None else callback
        self.exiting = Event()
        self._shutting_down = Event()
        self._subprocesses = []

        if os.name == "nt":
            profile = Path(os.path.expandvars("%LocalAppData%"))
        else:
            profile = Path(os.path.expanduser("~")) / ".config"

        self._temp_dir = Path(f"{self.NAME.lower()}_tmp")
        self._extracted_dir = self._temp_dir / "extracted"
        self._final_dir = self._temp_dir / "final"
        self._crack_dir = self._temp_dir / "crack"
        self._hashes_cache = f"{self.NAME.lower()}_files.cache"
        self._hashes = {}
        self._global_paths_cache = profile / "anadius" / "game_paths.cache"

        self._game_name = None
        self._language = None
        self._game_dir = None
        self._selected_dlcs = None

    def exiting_extra(self):
        """Extra stuff to do when exiting. Used only when subclassing."""
        pass

    def check_exiting(self):
        if self.exiting.is_set():
            for p in self._subprocesses:
                if p.poll() is None:
                    p.interrupt()

            self._save_hash_cache()

            try:
                for path in self._temp_dir.glob("TMP_*/"):
                    shutil.rmtree(path, ignore_errors=True)
            except (OSError, PermissionError):
                pass

            delete_empty_dirs(self._temp_dir)

            self.exiting_extra()

            raise ExitingError

    def shutdown(self):
        self.exiting.set()
        if not self._shutting_down.is_set():
            self._shutting_down.set()
            self.check_exiting()

    def run(self, *args, **kwargs):
        try:
            p = Popen2(*args, check_exiting=self.check_exiting, **kwargs)
        except FileNotFoundError:
            raise PatcherError(
                f"{args[0][0]} executable not found, it's possible that"
                " your anti-virus deleted it. If disabling your anti-virus"
                " doesn't help try downloading that executable"
                " and putting it in the same folder as this program."
            )
        except PermissionError:
            raise PatcherError(
                f"{args[0][0]} executable cannot be executed, make "
                "sure your anti-virus doesn't block this program."
            )
        except OSError as e:
            raise PatcherError(
                f"{args[0][0]} executable cannot be executed, make "
                "sure your anti-virus doesn't block this program."
                f"\n\nOriginal error message: {e}"
            )
        self._subprocesses.append(p)
        return p

    def _get_temp_file(self, tmp):
        i = 0
        while True:
            dst = tmp / f"dst_{i}"
            try:
                with open(dst, "x"):
                    pass
            except FileExistsError:
                i += 1
            except FileNotFoundError:
                self._create_folder(tmp)
            except OSError:
                raise PatcherError(
                    f"Can't create a temporary file ({tmp}), make "
                    "sure your anti-virus doesn't block this program."
                )
            else:
                break

        return dst

    def load_metadata(self, file_path_or_bytes):
        """
        Loads the metadata from ZIP. Returns `None` if (1) there's no metadata,
        (2) metadata can't be parsed or (3)
        Throws `myzipfile.BadZipFile` if not a ZIP file.
        """

        if isinstance(file_path_or_bytes, bytes):
            file = io.BytesIO(file_path_or_bytes)
        else:
            file = file_path_or_bytes

        # We just need the central directory parsed, no need to keep the ZIP open.
        with myzipfile.ZipFile(file) as zf:
            pass

        try:
            metadata = zf.read_metadata()
        except ValueError:
            return None

        patcher_version = metadata.get("patcher_version")
        if not isinstance(patcher_version, int) or patcher_version > self.VERSION:
            if isinstance(file_path_or_bytes, bytes):
                file_path_or_bytes = "<bytes>"
            raise NewerPatcherRequiredError(
                (
                    f"Newer version of the {self.NAME} is required to use this file:"
                    f"\n{file_path_or_bytes}"
                ),
                file_path_or_bytes,
            )

        return metadata

    def load_all_metadata(self, types=None):
        if len(os.getcwd()) > 100:
            raise PatcherError(
                "Windows is stupid so to ensure this program works properly move "
                fr'it to some shorter path, like C:\{self.NAME}'
            )
        write_check()

        if types is None:
            types = ("patch", "dlc")

        self.callback(CallbackType.HEADER, "Reading the metadata from files")

        all_metadata = {}
        for file in Path(".").glob("*"):
            if not file.is_file():
                continue

            try:
                metadata = self.load_metadata(file)
            except myzipfile.BadZipFile:
                continue

            self.callback(CallbackType.INFO, file)

            file = str(file)
            if metadata is None or metadata.get("type") not in types:
                self.callback(CallbackType.FAILURE, "BAD METADATA")
                continue

            game_name = metadata.get("game_name")
            metadata["extra"] = {"archive_path": file}
            try:
                all_metadata[game_name].append(metadata)
            except KeyError:
                all_metadata[game_name] = [metadata]

        if len(all_metadata) == 0:
            raise NoPatchesDLCsFoundError("No patch/DLC files found!")

        self._all_metadata = all_metadata
        return tuple(sorted(self._all_metadata.keys()))

    def check_dlcs(self):
        dlcs = {}

        # This is just a sanity check, I'm not adding a code for generating DLC zips in
        # the patch maker. I use that for The Sims 4 because those files don't change.
        patches = set(self._patches["delta"].keys())
        for dlc in self._dlcs:
            dlc_files = set(dlc["files"].keys())
            if len(patches & dlc_files) > 0:
                raise DLCPatchesNotImplementedError("DLC patches are not implemented.")

            name = dlc["name"]
            path = dlc["extra"]["archive_path"]
            try:
                dlcs[name].append(path)
            except KeyError:
                dlcs[name] = [path]

        for name, files in sorted(dlcs.items()):
            if len(files) > 1:
                files_str = "\n".join(sorted(files))
                raise DuplicatedDLCsError(
                    f'"{name}" DLC found in multiple files:\n{files_str}'
                )

    def _get_game_path(self, game_name):
        paths = cache.load(self._global_paths_cache)
        if paths is None:
            return None

        return paths.get(game_name)

    def _save_game_path(self, game_name, game_dir):
        paths = cache.load(self._global_paths_cache)
        if paths is None:
            paths = {}

        paths[game_name] = game_dir

        try:
            self._create_folder(self._global_paths_cache.parent)
        except:
            pass

        try:
            cache.save(self._global_paths_cache, paths)
        except FileNotFoundError:  # should happen only when folder creation failed - so for saving in appdata
            pass

    def pick_game(self, game_name, crack_missing_fatal=True):
        self.callback(CallbackType.HEADER, "Parsing the metadata")

        self._game_name = game_name

        metadata = self._all_metadata[game_name]
        self._all_metadata = None

        try:
            versions, self._patches = parse_patches(metadata, crack_missing_fatal)
        except KeyError:
            raise PatcherError(
                "KeyError exception caught while parsing the patches. "
                f"Run the {self.NAME} again. "
                f"If that doesn't work download {self.NAME} again."
            )
        self._dlcs = filter_metadata(metadata, "dlc")
        self.check_dlcs()

        path = self._get_game_path(game_name)

        return (
            versions,
            len(self._dlcs),
            list(sorted(self._patches["languages"].keys())),
            path,
        )

    def select_language(self, language):
        self._language = language
        del self._patches["languages"][language]

        optional = set(self._patches["optional"])
        for lang_files in self._patches["languages"].values():
            optional |= set(lang_files)

        self._patches["optional"] = list(sorted(optional))
        self._patches["languages"] = {}

    def _load_hash_cache(self):
        if (cached := cache.load(self._hashes_cache)) is not None:
            self._hashes = cached
            # Remove missing files from the cache
            files = set(self._hashes.keys())
            files -= {str(self._game_dir / file) for file in self._game_files.keys()}
            files -= {str(self._final_dir / file) for file in self._final_files.keys()}
            files -= {
                str(self._extracted_dir / file) for file in self._extracted_files.keys()
            }
            for file in files:
                del self._hashes[file]

    def _save_hash_cache(self, force=False):
        if len(self._hashes) > 0 or force:
            cache.save(self._hashes_cache, self._hashes)

    def check_files_quick(self, game_path):
        game_path = str(game_path).strip()
        self.callback(CallbackType.HEADER, "Checking files")

        if len(self._patches["languages"]) != 0:
            raise PatcherError("You didn't call `Patcher.select_language`!")

        files = set(self._patches["delta"].keys())
        files -= set(self._patches["full"].keys())
        files -= set(self._patches["optional"])

        all_files = set(self._patches["delta"].keys())
        all_files |= set(self._patches["full"].keys())
        all_files |= set(self._patches["optional"])
        for dlc in self._dlcs:
            all_files |= set(dlc["files"].keys())

        self._game_dir = Path(game_path)

        all_folders = {
            Path(file).parent.as_posix()
            for file in all_files
        }

        self._game_files = get_files_dict(self._game_dir, all_folders)
        self._final_files = get_files_dict(self._final_dir)
        self._extracted_files = get_files_dict(self._extracted_dir)
        self._load_hash_cache()

        game_files = set(self._game_files.keys())
        final_files = set(self._final_files.keys())
        extracted_files = set(self._extracted_files.keys())

        for file in sorted(files):
            if (
                file not in game_files
                and file not in final_files
                and file not in extracted_files
            ):
                raise FileMissingError(
                    f"{file} file is missing! You selected the wrong folder, you "
                    "didn't download all required patches, or your game installation "
                    "is corrupted."
                )

        all_dlcs = []
        missing_dlcs = []
        for dlc in self._dlcs:
            name = dlc["name"]
            all_dlcs.append(name)
            if len(set(dlc["files"].keys()) - game_files) > 0:
                missing_dlcs.append(name)

        return tuple(sorted(all_dlcs)), tuple(missing_dlcs)

    def patch(self, selected_dlcs):
        self._selected_dlcs = selected_dlcs
        # Deep copy - in case you want to run the patcher multiple times.
        try:
            metadata = json.loads(json.dumps(self._patches))
        except json.JSONDecodeError:
            raise PatcherError(
                "If you see this message then either you have bad RAM or your "
                "anti-virus messes with this program. Or cosmic rays flipped some"
                " ones and zeros, IDK."
            )

        self.add_selected_dlcs(metadata, selected_dlcs)

        files_info, all_delta = self.parse_metadata(metadata)

        local_files, local_patches = self.check_files(
            metadata, files_info, all_delta
        )

        to_delete = self.hash_files(
            metadata,
            files_info,
            all_delta,
            local_files,
            local_patches,
        )
        self.callback(CallbackType.PROGRESS, 100, 100)

        self._save_game_path(self._game_name, str(self._game_dir))

        # Not needed, all info already `in metadata["delta"]`
        del all_delta
        del local_patches

        best = self.find_best_updates(metadata, local_files, files_info, to_delete)

        del local_files
        del files_info

        self.delete_unnecessary_files(to_delete)

        to_extract = self.get_progress(best)

        self.extract_files(to_extract)

        updated, extra_files = self.apply_patches(best)

        self.callback(CallbackType.PROGRESS, 100, 100)

        crack = metadata["crack"]

        if len(updated) == 0 and (
            crack is None
            or not self.ask_question(
                "There's nothing to update, do you want to extract the crack anyway?"
            )
        ):
            pass
        else:
            self.extract_crack(crack, updated)

            if len(updated) > 0:
                write_check(self._game_dir)

                self.move_updated_files(updated, extra_files)

        self._delete_files(
            map(lambda x: self._game_dir / x, metadata["deleted"]), report=True
        )

        self.finished()

    def finished(self):
        self.callback(CallbackType.FINISHED, force_scroll=True)

    def add_selected_dlcs(self, metadata, selected_dlcs):
        for dlc in self._dlcs:
            if dlc["name"] in selected_dlcs:
                parse_other(metadata, dlc)

    def parse_metadata(self, metadata):
        # {"name": ("MD5", size)}
        files_info = get_hashes_and_sizes(metadata)

        # {"name": {"extension": ..., "MD5_from": ..., etc.}}
        all_delta = get_all_delta(metadata)

        return files_info, all_delta

    def check_files(self, metadata, files_info, all_delta):
        self._progress_total = 0

        local_files = {}
        delta = metadata["delta"]
        locations = (
            (self._game_files, self._game_dir, False),
            (self._final_files, self._final_dir, True),
            (self._extracted_files, self._extracted_dir, True),
        )
        for file in list(sorted(files_info.keys())):
            size = files_info[file][1]
            sizes = set([size])
            for patch in delta.get(file, []):
                # Only "size_from" is needed because "size_to"
                # from the last patch is the same as `size`.
                sizes.add(patch["size_from"])

            files = []

            for info_dict, directory, can_delete in locations:
                info = info_dict.get(file)

                if info is None:
                    continue

                try:
                    stat = info()
                except FileNotFoundError:
                    raise PatcherError(
                        f"Files deleted while {self.NAME} was working. Don't do that."
                        f" Run the {self.NAME} again."
                    )
                file_size = stat.st_size
                # If the size is different there's no patch available for that file.
                if file_size in sizes:
                    files.append(
                        {
                            "path": directory / file,
                            "size": file_size,
                            "mtime": stat.st_mtime,
                            "can_delete": can_delete,
                            "extracted": True,
                        }
                    )
                    self._progress_total += file_size

            if len(files) == 0:
                check_for_full_file(file, metadata, files_info)

                continue

            # Files with the same size as the expected one come first.
            files.sort(key=lambda x: -1 if x["size"] == size else 1)
            local_files[file] = files

        local_patches = {}
        for file in set(all_delta.keys()) & set(self._extracted_files.keys()):
            stat = self._extracted_files[file]()
            file_size = stat.st_size
            if file_size == all_delta[file]["size"]:
                local_patches[file] = {
                    "path": self._extracted_dir / file,
                    "size": file_size,
                    "mtime": stat.st_mtime,
                    "can_delete": True,
                    "extracted": True,
                }
                self._progress_total += file_size

        return local_files, local_patches

    def _progress(self, processed):
        self.check_exiting()
        self.callback(
            CallbackType.PROGRESS,
            self._progress_current + processed,
            self._progress_total
        )

    def _hash_file(self, info):
        path = info["path"]
        path_str = str(path)
        if (
            (cached := self._hashes.get(path_str)) is not None
            and cached[1] == info["size"]
            and cached[2] == info["mtime"]
        ):
            return cached[0], True

        self.callback(CallbackType.INFO, f"hashing {path_str}")

        try:
            md5 = hash_file(path, progress=self._progress)
        except FileNotFoundError:
            raise PatcherError(
                f'Can\'t hash "{path}" because it doesn\'t exist'
                "I don't know if you deleted it yourself or if your "
                "anti-virus did it..."
            )
        except (PermissionError, OSError) as e:
            raise AVButtinInError(
                f'Can\'t hash "{path}" file. Make sure your anti-virus'
                " doesn't block this program."
                "\nIf that doesn't help reboot your PC and try copying "
                "that file somewhere else (doesn't matter where). If you "
                "can copy the file - reset file permissions (see the readme"
                " file). If you can't copy the file - delete it, since it's"
                " corrupted anyway."
            )

        self._hashes[path_str] = [md5, info["size"], info["mtime"]]

        return md5, False

    def _hash_files(
        self,
        metadata,
        files_info,
        all_delta,
        local_files,
        local_patches,
    ):
        self._progress_current = 0
        self._progress(0)

        to_delete = []

        delta = metadata["delta"]
        for file in sorted(local_files.keys()):
            expected_md5, expected_size = files_info[file]
            expected_found = False

            md5s = set()
            patches = []
            for patch in delta.get(file, []):
                # Only "MD5_from" is needed because "MD5_to"
                # from the last patch is the same as `expected_md5`.
                md5s.add(patch["MD5_from"])
                patches.append(file + patch["extension"])

            hashed = []

            files = local_files[file]
            for info in files[::]:
                size = info["size"]

                if expected_found:
                    self._progress_total -= size
                    to_delete.append(info)
                    continue

                md5, cached = self._hash_file(info)
                info["MD5"] = md5

                if cached:
                    self._progress_total -= size
                else:
                    self._progress_current += size

                if md5 == expected_md5:
                    expected_found = True
                    to_delete += hashed
                    hashed = [info]

                    for patch_file in patches:
                        if (patch := local_patches.pop(patch_file, None)) is not None:
                            to_delete.append(patch)
                            self._progress_total -= patch["size"]
                elif md5 in md5s:
                    hashed.append(info)
                else:
                    to_delete.append(info)

            if len(hashed) == 0:
                check_for_full_file(file, metadata, files_info)

                del local_files[file]
                continue

            local_files[file] = hashed

        for file, info in sorted(local_patches.items()):
            md5, cached = self._hash_file(info)

            size = info["size"]
            if cached:
                self._progress_total -= size
            else:
                self._progress_current += size

            if md5 == all_delta[file]["MD5"]:
                all_delta[file].update(info)
            else:
                to_delete.append(info)

        self._save_hash_cache()

        return to_delete

    def hash_files(
        self,
        metadata,
        files_info,
        all_delta,
        local_files,
        local_patches,
    ):
        try:
            return self._hash_files(
                metadata,
                files_info,
                all_delta,
                local_files,
                local_patches,
            )
        except KeyError:
            raise PatcherError(
                "Patch metadata corrupted. Either patch file is corrupted or your"
                " anti-virus is messing with this program."
            )

    def _get_all_full_files(self, file, metadata, local_files):
        full_files = local_files.get(file, [])
        if (full := metadata["full"].get(file)) is not None:
            full_files.append(full)

        return full_files

    def _find_best_update(self, update):
        bytes_to_extract = 0
        for file in update:
            if not file.get("extracted", False):
                bytes_to_extract += file["size"]

        # No need to check how much to actually update, fewer patches = better
        return (bytes_to_extract, len(update))

    def find_best_updates(self, metadata, local_files, files_info, to_delete):
        best = {}
        for file, (md5, _) in sorted(files_info.items()):
            full_files = self._get_all_full_files(file, metadata, local_files)
            if len(full_files) == 0:
                raise PatcherError(
                    f"There are no full files for {file} and it's not optional. "
                    "This shouldn't happen, an error should've been thrown earlier."
                )

            updates = []
            patches = metadata["delta"].get(file, [])
            for full in full_files:
                update = [full]
                full_md5 = full["MD5"]

                if full_md5 != md5:
                    for i, info in reversed(list(enumerate(patches))):
                        if full_md5 == info["MD5_from"]:
                            update += patches[i:]
                            break

                    if len(update) == 1:
                        raise PatcherError(
                            f"No patches found for {file}. This shouldn't happen, "
                            "an error should've been thrown earlier."
                        )

                updates.append(tuple(update))

            updates.sort(key=self._find_best_update)
            best_update = updates[0]

            for info in patches:
                if info.get("extracted", False) and info not in best_update:
                    to_delete.append(info)

            # Skip if the updated file is already in the game folder.
            if (
                len(best_update) == 1
                and (path := best_update[0].get("path")) is not None
                and path == self._game_dir / file
            ):
                continue

            best[file] = best_update

        return best

    def _delete_file(self, path, report=False, first_time=True):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except:
            if first_time:
                try:
                    os.chmod(path, 0o755)
                except:
                    pass
                else:
                    return self._delete_file(path, report, first_time=False)

            if report:
                self.callback(CallbackType.INFO, f"Failed to delete {str(path)}")
            return False
        return True

    def _delete_files(self, paths, report=False):
        for path in paths:
            self._delete_file(path, report=report)

    def delete_unnecessary_files(self, to_delete):
        paths = []
        for info in to_delete:
            if info.get("can_delete", False) and (path := info.get("path")) is not None:
                paths.append(path)

        if len(paths) == 0:
            return

        self.callback(CallbackType.HEADER, "Deleting unnecessary files")

        self._delete_files(paths, report=True)

    def get_progress(self, best):
        maximum = 0
        to_extract = {}
        for file, updates in sorted(best.items()):
            patches_size = 0

            for i, info in enumerate(updates):
                name = file

                if i > 0:
                    name += info["extension"]
                    patches_size += info["size"]

                if (path := info.get("path")) is None:
                    info["path"] = path = self._extracted_dir / name

                if not info.get("extracted", False):
                    maximum += info["size"]
                    archive = info["archive_path"]
                    try:
                        to_extract[archive].append((name, info))
                    except KeyError:
                        to_extract[archive] = [(name, info)]

            # If there are xdelta patches:
            if (count := len(updates)) > 1:
                # Add filesize of the final file.
                maximum += updates[-1]["size_to"]
                # If there are two or more patches:
                if count > 2:
                    # Add size of the combined patches.
                    maximum += patches_size

        self._progress_current = 0
        self._progress_total = maximum

        return to_extract

    def _check_space(self, required, path=None):
        if path is None:
            path = Path(".")
        else:
            path = Path(path)

        try:
            path = path.resolve()
        except (OSError, FileNotFoundError) as e:
            if isinstance(e, OSError):
                if e.winerror == 433:
                    error_message = "A device which does not exist was specified."
                elif e.winerror == 1117:
                    error_message = (
                        "The request could not be performed "
                        "because of an I/O device error"
                    )
                else:
                    error_message = None
            elif isinstance(e, FileNotFoundError):
                if e.winerror == 53:
                    error_message = "Network path not found."
                else:
                    error_message = None

            if error_message is None:
                raise
            else:
                raise PatcherError(
                    f"{error_message} Make sure you select the right folder and "
                    "your anti-virus doesn't block this program. "
                    f"Error when resolving: {str(path)}"
                )

        try:
            if shutil.disk_usage(path).free < required:
                raise NotEnoughSpaceError(
                    f"You don't have enough space on your {path.anchor} drive!\n\n"
                    f'{self.NAME} stores temporary files in "{self._temp_dir}". '
                    f"This folder is located in the same place as the {self.NAME}, "
                    f'in "{os.getcwd()}". Make some space or move all {self.NAME} '
                    "files somewhere else.\n\nIf you can't make more space check if "
                    f'there are any files in "{self._final_dir}". These are updated '
                    "game files and you can move them to your game folder - that "
                    "should free up some space."
                )
        except FileNotFoundError:
            raise PatcherError(
                "Can't check available disk space. "
                "Make sure your anti-virus doesn't block this program."
            )

    def do_after_extraction(self, archive, error_occured):
        if error_occured:
            raise PatcherError(
                f'An error occured when extracting "{archive}". Try again, '
                "and if you get the same error - redownload this archive."
            )

    def extract_files(self, to_extract):
        if len(to_extract) == 0:
            return

        self.callback(CallbackType.HEADER, "Extracting files")

        for archive, files in to_extract.items():
            all_extra = True
            for _, info in files:
                if info.get("type") != "extra":
                    all_extra = False
                    break

            required = sum(map(lambda x: x[1]["size"], files))
            self._check_space(required)

            error_occured = False

            try:
                with myzipfile.ZipFile(archive) as zf:
                    for file, info in files:
                        is_extra = info.get("type") == "extra"
                        self.callback(CallbackType.INFO, f"extracting {file}")

                        self._create_folder(info["path"].parent)

                        try:
                            with zf.open(file) as fsrc, open(
                                info["path"], "wb"
                            ) as fdst:
                                copyfileobj(fsrc, fdst, self._progress)
                        except (myzipfile.BadZipFile, zlib.error, EOFError):
                            if not is_extra:
                                error_occured = True
                            self.callback(CallbackType.FAILURE, "FAILED")
                        except OSError as e:
                            if e.errno == errno.ENOSPC:
                                raise NotEnoughSpaceError(
                                    "You don't have enough space on "
                                    f"{Path(file).anchor} drive!"
                                )
                            if is_extra:
                                self.callback(CallbackType.FAILURE, "FAILED")
                            else:
                                raise PatcherError(
                                    f"Extraction failed. Make sure your "
                                    "anti-virus doesn't block this program."
                                )
                        else:
                            info["extracted"] = True

                        self._progress_current += info["size"]
            except FileNotFoundError as e:
                if all_extra:
                    self.callback(
                        CallbackType.INFO,
                        f"\nArchive {archive} missing but it's optional.\n",
                    )
                else:
                    raise PatcherError(
                        f'"{e.filename}" not found. Run this program again and'
                        " don't delete any files while it's running."
                    )

            self.do_after_extraction(archive, error_occured)

    def _copy_file(self, src, dst, required_size=None, name=None):
        if name is None:
            name = str(src)

        self.callback(CallbackType.INFO, f"copying {name}")

        src = Path(src)
        dst = Path(dst)

        if required_size is None:
            required_size = src.stat().st_size

        self._create_folder(dst.parent)
        self._check_space(required_size, dst.parent)

        try:
            shutil.copy(src, dst)
        except OSError:
            raise PatcherError(
                f'Can\'t copy "{str(src)}". '
                "Make sure your anti-virus doesn't block this program."
            )

    def _xdelta(self, args, expected_size, tmp):
        if os.name == "nt":
            for i, arg in enumerate(args):
                try:
                    arg.encode("ascii")
                except UnicodeEncodeError:
                    safe_path = get_short_path(arg)
                    if safe_path is None:
                        safe_path = self._get_temp_file(tmp)
                        try:
                            self._copy_file(arg, safe_path)
                        except FileNotFoundError as e:
                            if e.winerror == 3:
                                raise PatcherError(
                                    "The system cannot find the specified path. "
                                    "Can't copy the file to patch."
                                )
                            raise
                    args[i] = safe_path

        dst = self._get_temp_file(tmp)

        self._check_space(expected_size * 1.2)

        p = self.run(["xdelta3", "-v", "-f"] + args + [str(dst)])

        if "merge" in args:
            while p.running(seconds=1):
                try:
                    size = dst.stat().st_size
                except (FileNotFoundError, OSError):
                    size = 0
                self._progress(size)

            unparsed_lines = [
                line.decode(errors="replace")
                for line in p.lines(stderr=True)
            ]
        else:
            unparsed_lines = []
            processed_size = 0
            for line in p.lines(stderr=True):
                if (
                    m := re.match(
                        br"xdelta3: \d+: in .*? out (\d+(?:\.\d+)?) ((?:[KMGT]i)?B)",
                        line,
                    )
                ) is None:
                    unparsed_lines.append(line.decode(errors="replace"))
                    continue

                processed_size += parse_size(*m.groups())
                self._progress(processed_size)

        if p.returncode != 0:
            lines_str = "\n".join(unparsed_lines).strip()
            parsed_lines_str = "\n".join(
                x
                for x in unparsed_lines
                if not (
                    (
                        x.startswith("xdelta3: source")
                        and " source size " in x
                        and " blksize " in x
                        and " window " in x
                    )
                    or x.startswith("xdelta3: finished in ")
                )
            ).strip()

            if (
                "xdelta3: further input required: " in lines_str
                or "Data error (cyclic redundancy check)" in lines_str
                or "xdelta3: lzma decoding error: XD3_INTERNAL" in lines_str
                or "xdelta3: nothing to output: " in lines_str
                or "xdelta3: unknown secondary compressor ID: " in lines_str
                or "xdelta3: internal merge error: offset mismatch" in lines_str
                or "xdelta3: eof in decode: XD3_INVALID_INPUT" in lines_str
                or "xdelta3: not a VCDIFF input: XD3_INVALID_INPUT" in lines_str
                or "xdelta3: Internal error in merge: XD3_INTERNAL" in lines_str
                or "xdelta3: Invalid copy offset in merge: XD3_INVALID_INPUT" in lines_str
                or "xdelta3: unrecognized window indicator bits set: XD3_INVALID_INPUT" in lines_str
            ):
                raise XdeltaError(
                    'Failed to apply the patch, try using the "Repair" button!'
                    " And if that doesn't help try disabling your anti-virus."
                    f"\n\nOriginal output:\n{lines_str}"
                )
            if "xdelta3: please verify the source file with sha1sum" in lines_str:
                raise XdeltaError(
                    'Failed to apply the patch, try using the "Repair" button!'
                )
            if "xdelta3: write failed: " in lines_str:
                raise XdeltaError(
                    "Failed to apply the patch, can't write to a file. Try disabling"
                    " your anti-virus or copying this program somewhere else. "
                    "And make sure you have enough free space available."
                )
            if "xdelta3: out of memory: " in lines_str:
                if os.name == "nt":
                    extra = "Pagefile on Windows OS"
                elif sys.platform.startswith("darwin"):
                    extra = "This shouldn't happen on MacOS"
                else:
                    extra = "Swap parition on Linux"

                raise XdeltaError(
                    "Failed to apply the patch, not enough memory. Try increasing"
                    f" your virtual memory. ({extra}.)"
                )

            if "xdelta3: malloc: " in lines_str:
                raise XdeltaError(
                    "Failed to apply the patch, can't allocate the memory. "
                    "Try closing all programs and disabling your anti-virus."
                )

            if "Data error (cyclic redundancy check)" in lines_str:
                raise XdeltaError(
                    "Failed to apply the patch, CRC check failed. Try using the "
                    "Repair button and if that doesn't help disable your anti-virus."
                )

            if "xdelta3: input read failed" in lines_str:
                raise XdeltaError(
                    f'Failed to apply the patch, can\'t read from file.'
                    " Make sure that your anti-virus doesn't block this program."
                )

            m = re.search(
                r"xdelta3: file open failed: (?:read|write): (.*?): ", lines_str
            )
            if m is not None:
                raise XdeltaError(
                    f'Failed to apply the patch, can\'t open "{m.group(1)}".'
                )

            if parsed_lines_str == "":
                raise XdeltaError(
                    "Failed to apply the patch, no error message specified."
                    " Try disabling your anti-virus."
                )
            if p.returncode != 1:
                raise XdeltaError(
                    f"Failed to apply the patch, unknown return code ({p.returncode})."
                    " Try disabling your anti-virus."
                    f"\n\nOriginal output:\n{lines_str}"
                )

            raise UnhandledError(
                f"Failed to apply the patch!\nReturn code: {p.returncode}\n{lines_str}"
            )
            # raise XdeltaError(f"Failed to apply the patch:\n{lines_str}")

        self._progress_current += expected_size

        return dst

    def _combine_updates(self, updates, *args):
        arguments = ["merge"]
        for info in updates[1:]:
            arguments.append("-m")
            arguments.append(str(info["path"]))
        arguments.pop(-2)

        return self._xdelta(arguments, *args)

    def _apply_update(self, src, update, *args):
        return self._xdelta(["-d", "-s", str(src), str(update)], *args)

    def apply_patches(self, best):
        updated = {}
        extra_files = set()

        if len(best) == 0:
            return updated, extra_files

        self.callback(CallbackType.HEADER, "Updating files")

        for file, updates in sorted(best.items()):
            dst = self._final_dir / file

            src = updates[0]["path"]
            tmp = None

            if len(updates) == 1:
                info = updates[0]
                if info.get("type") == "extra":
                    if not info.get("extracted", False):
                        continue
                    else:
                        extra_files.add(file)
                updated_file = src
                expected_size = info["size"]
            else:
                self.callback(CallbackType.INFO, f"updating {file}")

                tmp = None
                for _ in range(5):
                    try:
                        tmp = Path(tempfile.mkdtemp(dir=self._temp_dir, prefix="TMP_"))
                    except (FileNotFoundError, OSError, PermissionError):
                        continue
                    else:
                        break
                if tmp is None:
                    raise PatcherError(
                        f"Can't create a temporary folder, "
                        "disable your anti-virus and try again."
                    )

                if len(updates) == 2:
                    update = updates[1]["path"]
                else:
                    combined_size = sum(map(lambda x: x["size"], updates[1:]))
                    update = self._combine_updates(updates, combined_size, tmp)

                expected_size = updates[-1]["size_to"]
                updated_file = self._apply_update(src, update, expected_size, tmp)

            updated[file] = (dst, self._game_dir / file, expected_size)

            if updated_file != dst:
                self._create_folder(dst.parent)
                try:
                    updated_file.replace(dst)
                except FileNotFoundError:
                    raise PatcherError(
                        f'"{str(updated_file)}" not found, '
                        "disable your anti-virus and try again."
                    )
                except (PermissionError, OSError):
                    raise PatcherError(
                        "Can't replace a file. Make sure your "
                        "anti-virus doesn't block this program."
                    )

            # After file patching is done delete the unnecessary files.
            if tmp is not None:
                shutil.rmtree(tmp, ignore_errors=True)
            to_delete = [
                path
                for info in updates
                if (path := info["path"]) != dst and info.get("can_delete", True)
            ]
            self._delete_files(to_delete, report=False)

        return updated, extra_files

    def _get_crack_path(self, crack):
        """
        That also is added mainly for Sims 4 Updater
        """
        return Path(crack["filename"])

    def extract_crack(self, crack, updated):
        if crack is None:
            return

        self.callback(CallbackType.HEADER, "Extracting the crack")

        try:
            if self._crack_dir.exists():
                shutil.rmtree(self._crack_dir, ignore_errors=True)
        except FileNotFoundError:
            raise PatcherError(
                f'Can\'t check if "{str(self._crack_dir)}" exists, '
                "make sure your anti-virus doesn't block this program."
            )

        if self._crack_dir.exists():
            time.sleep(1)
            if self._crack_dir.exists():
                try:
                    shutil.rmtree(self._crack_dir, ignore_errors=False)
                except (OSError, FileNotFoundError, PermissionError) as e:
                    if e.filename == str(self._crack_dir):
                        pass # deleted?
                    else:
                        raise PatcherError(
                            f'Can\'t delete "{e.filename}", '
                            "make sure your anti-virus doesn't block this program."
                        )

        crack_path = str(self._get_crack_path(crack))

        args = [
            "unrar",
            "x",
            "-p-",
            "-o+",
            crack_path,
            # UnRAR is stupid and requires a folder separator at the end of the
            # extract dir. Thankfully forward slash works on Windows too.
            str(self._crack_dir) + "/",
        ]
        if (password := crack.get("pass")) is not None:
            args.insert(3, f"-p{password}")

        p = self.run(args)

        # Just wait until the extraction is complete.
        while p.running(100):
            pass

        stdout = p.stdout.read().decode(errors="replace").strip()
        stderr = p.stderr.read().decode(errors="replace").strip()

        error_message = None

        if p.returncode == 0:
            pass
        elif p.returncode in UNRAR_ERRORS:
            error_message = UNRAR_ERRORS[p.returncode]
        elif p.returncode == 7 and "ERROR: Unknown option" in stdout:
            "Unknown option. "
        elif p.returncode == 10:
            error_message = f'"{crack_path}" doesn\'t exist. '
        elif p.returncode == 11:
            error_message = (
                f"Wrong password ({password}) or the "
                f'archive ("{crack_path}") is corrupted. '
            )
        elif p.returncode == 259 or (stdout == "" and stderr == ""):
            error_message = ""
        elif p.returncode > 259 and (
            "Write error in the file" in stderr
            or "winedbg: Internal crash at 0x" in stdout
        ):
            error_message = ""
        elif p.returncode in (0xC0000005, 0xFFFFFFFF):
            error_message = ""
        else:
            # raise UnrarError(
            raise UnhandledError(
                "Failed to extract the crack:\n"
                f"Return code: {p.returncode}\n"
                f"[STDOUT] {stdout}\n[STDERR] {stderr}"
            )

        if error_message is not None:
            raise UnrarError(
                f"Can't extract the crack. {error_message}Make "
                "sure your anti-virus doesn't block this program."
            )

        crack_files = get_files_dict(self._crack_dir)
        for file, stat in sorted(crack_files.items()):
            size = stat().st_size
            updated[file] = (self._crack_dir / file, self._game_dir / file, size)

    def _create_folder(self, path):
        for _ in range(5):
            try:
                path.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError, FileExistsError):
                pass
            else:
                return

        raise PatcherError(
            f'Can\'t create folder "{str(path)}", '
            "make sure your anti-virus doesn't block this program."
        )

    def move_updated_files(self, updated, extra_files):
        self.callback(CallbackType.HEADER, "Moving files")

        self._progress_total = sum(map(lambda x: x[2], updated.values()))
        self._progress_current = 0
        self._progress(0)

        files_to_delete = []

        for file, (src, dst, size) in sorted(updated.items()):
            self.callback(CallbackType.INFO, f"moving {file}")

            self._create_folder(dst.parent)

            self._delete_file(dst)

            self._check_space(size, dst.parent)

            delete_error_message = LAST_STEP_ERROR.format(
                action="delete",
                path=str(dst),
                final=self._final_dir,
                crack=self._crack_dir,
                game=self._game_dir,
            )
            try:
                if dst.exists():
                    dst.unlink()
            except PermissionError:
                if file in extra_files:
                    continue
                raise WritePermissionError(delete_error_message)
            except OSError as e:
                if file in extra_files:
                    continue
                raise PatcherError(delete_error_message)

            move_error_message = LAST_STEP_ERROR.format(
                action="move",
                path=file,
                final=self._final_dir,
                crack=self._crack_dir,
                game=self._game_dir,
            )
            try:
                src.replace(dst)
            except PermissionError:
                if file in extra_files:
                    continue
                raise WritePermissionError(move_error_message)
            except FileNotFoundError:
                if file in extra_files:
                    continue
                raise PatcherError(
                    f'Can\'t move {file}, because it doesn\'t exist. Make sure'
                    " your anti-virus doesn't delete any files."
                )
            except OSError as e:
                if e.errno != errno.EXDEV:
                    if file in extra_files:
                        continue
                    raise PatcherError(move_error_message)

                copy_error_message = LAST_STEP_ERROR.format(
                    action="copy",
                    path=file,
                    final=self._final_dir,
                    crack=self._crack_dir,
                    game=self._game_dir,
                )
                try:
                    with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
                        copyfileobj(fsrc, fdst, self._progress)
                except PermissionError:
                    if file in extra_files:
                        continue
                    raise WritePermissionError(copy_error_message)
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        raise NotEnoughSpaceError(
                            "You don't have enough space on "
                            f"{Path(dst).anchor} drive!"
                        )
                    else:
                        if file in extra_files:
                            continue
                        raise PatcherError(copy_error_message)

                files_to_delete.append(src)

                try:
                    shutil.copystat(src, dst)
                except (OSError, PermissionError, FileNotFoundError) as e:
                    pass

            self._progress_current += size
            self._progress(0)

        self._delete_files(files_to_delete, report=True)

    def _sleep(self, seconds):
        nanoseconds = seconds * (10 ** 9)
        start = time.time_ns()
        while time.time_ns() - start < nanoseconds:
            self.check_exiting()
            time.sleep(0.1)
        self.check_exiting()

    def __del__(self):
        try:
            self.shutdown()
        except ExitingError:
            pass
