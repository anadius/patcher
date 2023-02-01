"""
This module is an improved `zipfile` module. Changes:
* fixed function for stripping the `extra` field of file header
+ added `compresslevel` support for LZMA compression
  possible values: integer from 0 to 9 or a filter dict, like `{"dict_size": 67108864}`
  https://docs.python.org/3/library/lzma.html#specifying-custom-filter-chains
+ when `ZipFile.store_if_smaller` is set to True and the compressed size is bigger than
  the uncompressed size - scrap the compressed data and store file without compression;
+ added functions for writing/reading raw bytes or Python objects (anything that's
  JSON serializable) to `extra` fields of file headers (up to 64KiB per file/folder)
"""

import importlib.util
import struct
import lzma
import json
import io

from shutil import COPY_BUFSIZE

__all__ = [
    "ExtraTooLong",
    "BadZipFile",
    "ZIP_STORED",
    "ZIP_DEFLATED",
    "ZIP_BZIP2",
    "ZIP_LZMA",
    "is_zipfile",
    "ZipInfo",
    "ZipFile",
    "LargeZipFile",
]

"""
Import `zipfile` as `_z` and then monkey patch it while leaving `zipfile` intact
https://stackoverflow.com/a/11285504/2428152
"""
SPEC_ZIPFILE = importlib.util.find_spec("zipfile")
_z = importlib.util.module_from_spec(SPEC_ZIPFILE)
SPEC_ZIPFILE.loader.exec_module(_z)
del SPEC_ZIPFILE

BadZipFile = _z.BadZipFile
ZIP_STORED = _z.ZIP_STORED
ZIP_DEFLATED = _z.ZIP_DEFLATED
ZIP_BZIP2 = _z.ZIP_BZIP2
ZIP_LZMA = _z.ZIP_LZMA
is_zipfile = _z.is_zipfile
ZipInfo = _z.ZipInfo
LargeZipFile = _z.LargeZipFile

"""
Monkey patch broken function
https://bugs.python.org/issue44067
"""


def _strip_extra(extra, xids):
    # Remove Extra Fields with specified IDs.
    unpack = _z._EXTRA_FIELD_STRUCT.unpack
    modified = False
    buffer = []
    i = 0
    while i + 4 <= len(extra):
        xid, xlen = unpack(extra[i : i + 4])
        j = i + 4 + xlen
        if xid in xids:
            modified = True
        else:
            buffer.append(extra[i:j])
        i = j
    if not modified:
        return extra
    return b"".join(buffer)


_z._strip_extra = _strip_extra

"""
Let LZMA compression use `compresslevel` - it can be integer from 0 to 9
or a dict with params specified at
https://docs.python.org/3/library/lzma.html#specifying-custom-filter-chains
"""


class _LZMACompressor(_z.LZMACompressor):
    def __init__(self, compresslevel):
        if isinstance(compresslevel, dict):
            self._props = compresslevel
        elif isinstance(compresslevel, int):
            self._props = {"preset": compresslevel}
        else:
            self._props = {}
        super().__init__()

    def _init(self):
        self._props.update({"id": lzma.FILTER_LZMA1})
        props = lzma._encode_filter_properties(self._props)
        self._comp = lzma.LZMACompressor(
            lzma.FORMAT_RAW,
            filters=[lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)],
        )
        return struct.pack("<BBH", 9, 4, len(props)) + props


_get_compressor_original = _z._get_compressor


def _get_compressor(compress_type, compresslevel=None):
    if compress_type == ZIP_LZMA:
        return _LZMACompressor(compresslevel)
    else:
        return _get_compressor_original(compress_type, compresslevel)


_z._get_compressor = _get_compressor


(_EXTRA_BYTES_HEADER_ID,) = struct.unpack("<H", b"an")  # 28257
(_EXTRA_MAX_SIZE,) = struct.unpack("<H", b"\xFF\xFF")  # 65535
_ZIP64_MAX_EXTRA_SIZE = struct.calcsize("<HHQQQ")  # 28


class ExtraTooLong(Exception):
    """
    Raised when extra bytes are longer than the space available. Each file
    header can store up to 64KiB-1, more files in archive means more space.
    """


def _get_extra_data(extra, extra_id):
    unpack = _z._EXTRA_FIELD_STRUCT.unpack
    i = 0
    while i + 4 <= len(extra):
        xid, xlen = unpack(extra[i : i + 4])
        j = i + 4 + xlen
        if xid == extra_id:
            return extra[i + 4 : j]
        i = j
    return None


class ZipFile(_z.ZipFile):
    def __init__(self, *args, store_if_smaller=False, **kwargs):
        self.store_if_smaller = store_if_smaller
        super().__init__(*args, **kwargs)

    def write(self, *args, **kwargs):
        super().write(*args, **kwargs)

        zinfo = self.filelist[-1]
        if self.store_if_smaller and zinfo.compress_size > zinfo.file_size:
            self.start_dir = zinfo.header_offset
            self.fp.seek(zinfo.header_offset)
            self.fp.truncate()
            del self.NameToInfo[zinfo.filename]
            self.filelist.remove(zinfo)

            kwargs["compress_type"] = ZIP_STORED
            super().write(*args, **kwargs)

    def write_extra_bytes(self, extra_bytes, header_id=_EXTRA_BYTES_HEADER_ID):
        """
        Store `extra_bytes` in `extra` fileds of file headers in central directory
        """
        for zip_info in self.filelist:
            # Strip old data
            zip_info.extra = _strip_extra(zip_info.extra, (header_id,))
        for zip_info in self.filelist:
            if len(extra_bytes) == 0:
                break
            """
            Calculate free space while leaving enough for max size of
            ZIP64 header and 4 bytes for our own header
            """
            free_space = (
                _EXTRA_MAX_SIZE
                - _ZIP64_MAX_EXTRA_SIZE
                - len(_strip_extra(zip_info.extra, (1,)))
                - _z._EXTRA_FIELD_STRUCT.size
            )
            chunk = extra_bytes[:free_space]
            chunk_size = len(chunk)
            zip_info.extra += _z._EXTRA_FIELD_STRUCT.pack(header_id, chunk_size) + chunk
            extra_bytes = extra_bytes[chunk_size:]
        if len(extra_bytes) != 0:
            raise ExtraTooLong("Extra bytes too long")
        self._didModify = True
        """
        `zipfile` rewrites the central directory but doesn't truncate the file
        leading to corrupted ZIP if new extra bytes are shorter than the old ones
        """
        self.fp.seek(self.start_dir)
        self.fp.truncate()

    def write_metadata(self, obj, header_id=_EXTRA_BYTES_HEADER_ID):
        """
        Serialize `obj` to a JSON formatted str, compress it with `lzma` and write
        resulting bytes with `write_extra_bytes`
        """
        compressed = io.BytesIO()
        with lzma.open(compressed, "wt", preset=9) as lz:
            lz.write(json.dumps(obj))
        self.write_extra_bytes(compressed.getvalue(), header_id)

    def read_extra_bytes(self, header_id=_EXTRA_BYTES_HEADER_ID):
        """
        Read bytes written with `write_extra_bytes`
        """
        extra_bytes = []
        for zip_info in self.filelist:
            extra = _get_extra_data(zip_info.extra, header_id)
            if extra is None:
                break
            extra_bytes.append(extra)
        return b"".join(extra_bytes)

    def read_metadata(self, header_id=_EXTRA_BYTES_HEADER_ID):
        """
        Read object written with `write_metadata`
        """
        compressed = io.BytesIO(self.read_extra_bytes(header_id))
        compressed.seek(0)
        try:
            with lzma.open(compressed, "rt") as lz:
                return json.loads(lz.read())
        except (EOFError, lzma.LZMAError, json.JSONDecodeError):
            raise ValueError("Could not read the metadata")

    def _copy_file_from(self, zinfo_or_arcname, zfile):
        # Ensure we have ZipInfo object
        if not isinstance(zinfo_or_arcname, ZipInfo):
            zinfo = zfile.getinfo(zinfo_or_arcname)
        else:
            zinfo = zinfo_or_arcname

        # Get a file list from the source ZIP sorted by header offset
        filelist = list(sorted(zfile.filelist, key=lambda x: x.header_offset))
        index = filelist.index(zinfo)
        # Start of the raw data
        start = zinfo.header_offset
        # End of the raw data - header offset of the next file or offset of the
        # start directory of the ZIP
        try:
            end = filelist[index + 1].header_offset
        except IndexError:
            end = zfile.start_dir
        bytes_to_copy = end - start

        position = zfile.fp.tell()
        zfile.fp.seek(start)
        self.fp.seek(self.start_dir)

        new_zinfo = ZipInfo()
        for name in ZipInfo.__slots__:
            setattr(new_zinfo, name, getattr(zinfo, name))
        new_zinfo.header_offset = self.start_dir

        self._didModify = True

        while bytes_to_copy > 0 and (
            chunk := zfile.fp.read(min(bytes_to_copy, COPY_BUFSIZE))
        ):
            self.fp.write(chunk)
            bytes_to_copy -= len(chunk)

        zfile.fp.seek(position)

        # Revert changes and raise an error in case we didn't write the whole file
        if bytes_to_copy > 0:
            self.fp.seek(self.start_dir)
            self.fp.truncate()
            raise EOFError

        self.filelist.append(new_zinfo)
        self.NameToInfo[new_zinfo.filename] = new_zinfo

        self.start_dir = self.fp.tell()

    def copy_file_from(self, zinfo_or_arcname, zfile_or_file):
        """
        Copy file from another ZIP without recompressing it
        """

        # Ensure _copy_file_from gets a ZipFile object
        if isinstance(zfile_or_file, ZipFile):
            return self._copy_file_from(zinfo_or_arcname, zfile_or_file)
        else:
            with ZipFile(zfile_or_file) as zfile:
                return self._copy_file_from(zinfo_or_arcname, zfile)
