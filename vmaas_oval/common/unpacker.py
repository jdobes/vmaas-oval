import bz2
import gzip
import lzma
from typing import Callable

from vmaas_oval.common.logger import get_logger

LOGGER = get_logger(__name__)

DEFAULT_CHUNK_SIZE = 1048576


def _get_unpack_func(file_path: str) -> Callable:
    if file_path.endswith(".gz"):
        return gzip.open
    if file_path.endswith(".xz"):
        return lzma.open
    if file_path.endswith(".bz2"):
        return bz2.open
    return None


def unpack_file(file_path: str) -> str:
    unpacked_file_path = file_path
    unpack_func = _get_unpack_func(file_path)
    if unpack_func:
        with unpack_func(file_path, "rb") as packed:
            unpacked_file_path = file_path.rsplit(".", maxsplit=1)[0]
            with open(unpacked_file_path, "wb") as unpacked:
                while True:
                    chunk = packed.read(DEFAULT_CHUNK_SIZE)
                    if chunk == b"":
                        break
                    unpacked.write(chunk)
    return unpacked_file_path
