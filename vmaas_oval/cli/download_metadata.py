import argparse
import json
import os

from vmaas_oval.common.constants import DEFAULT_METADATA_DIR
from vmaas_oval.common.downloader import download_file
from vmaas_oval.common.logger import init_logging, get_logger

LOGGER = get_logger(__name__)

REPO_CPE_MAP_URL = "https://access.redhat.com/security/data/metrics/repository-to-cpe.json"
OVAL_FEED_BASE_URL = "https://access.redhat.com/security/data/oval/v2/"


def download_repo_cpe_map(metadata_dir: str):
    success = download_file(REPO_CPE_MAP_URL, os.path.join(metadata_dir, "repository-to-cpe.json"))
    LOGGER.info("Downloaded Repository to CPE mapping, success=%s", success)


def download_oval_files(metadata_dir: str):
    local_feed_path = os.path.join(metadata_dir, "feed.json")
    success = download_file(f"{OVAL_FEED_BASE_URL}feed.json", local_feed_path)
    LOGGER.info("Downloaded OVAL feed JSON, success=%s", success)

    with open(local_feed_path, 'r', encoding='utf8') as feed_file:
        feed = json.load(feed_file)
    total_files_cnt = len(feed["feed"]["entry"])
    for idx, entry in enumerate(feed["feed"]["entry"], start=1):
        local_path = os.path.join(metadata_dir, entry["content"]["src"].replace(OVAL_FEED_BASE_URL, ""))
        os.makedirs(os.path.dirname(local_path), exist_ok=True)  # Make sure subdirs exist
        success = download_file(entry["content"]["src"], local_path)
        LOGGER.info("Downloaded OVAL stream %s [%s/%s], success=%s", entry["id"], idx, total_files_cnt, success)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download CPE and OVAL metadata.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-m", "--metadata-dir", default=DEFAULT_METADATA_DIR, help="dir containing downloaded metadata")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)

    os.makedirs(args.metadata_dir, exist_ok=True)
    
    download_repo_cpe_map(args.metadata_dir)
    download_oval_files(args.metadata_dir)
