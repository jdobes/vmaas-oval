import requests

from vmaas_oval.common.logger import get_logger

LOGGER = get_logger(__name__)

DEFAULT_CHUNK_SIZE = 1048576
VALID_HTTP_CODES = {200}


def download_file(url: str, target_path: str) -> bool:
    with open(target_path, "wb") as file_handle:
        with requests.get(url, stream=True, allow_redirects=True) as response:
            while True:
                chunk = response.raw.read(DEFAULT_CHUNK_SIZE, decode_content=True)
                if chunk == b"":
                    break
                file_handle.write(chunk)
            LOGGER.debug("Downloaded %s -> %s: HTTP %s", url, target_path, response.status_code)
            return response.status_code in VALID_HTTP_CODES
