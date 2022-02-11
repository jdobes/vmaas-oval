import time

import requests
from requests.exceptions import ConnectionError

from vmaas_oval.common.logger import get_logger

LOGGER = get_logger(__name__)

DEFAULT_CHUNK_SIZE = 1048576
VALID_HTTP_CODES = {200}
RETRIES = 3


def _download_file(url: str, target_path: str) -> bool:
    with open(target_path, "wb") as file_handle:
        with requests.get(url, stream=True, allow_redirects=True) as response:
            while True:
                chunk = response.raw.read(DEFAULT_CHUNK_SIZE, decode_content=True)
                if chunk == b"":
                    break
                file_handle.write(chunk)
            LOGGER.debug("Downloaded %s -> %s: HTTP %s", url, target_path, response.status_code)
            return response.status_code in VALID_HTTP_CODES


def download_file(url: str, target_path: str) -> bool:
    for idx in range(RETRIES):
        try:
            return _download_file(url, target_path)
        except ConnectionError:
            if idx < RETRIES - 1:
                LOGGER.warning("Connection failed, retrying: %s", url)
                time.sleep(5)
            else:
                LOGGER.error("Connection failed: %s", url)
    return False
