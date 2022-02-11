import argparse
import os

from vmaas_oval.common.constants import DEFAULT_METADATA_DIR, REPO_CPE_MAP_URL, OVAL_FEED_BASE_URL
from vmaas_oval.common.downloader import download_file
from vmaas_oval.common.logger import init_logging, get_logger
from vmaas_oval.parsers.oval_feed import OvalFeed

LOGGER = get_logger(__name__)


def download_repo_cpe_map(metadata_dir: str):
    success = download_file(REPO_CPE_MAP_URL, os.path.join(metadata_dir, "repository-to-cpe.json"))
    LOGGER.info("Downloaded Repository to CPE mapping, success=%s", success)


def download_oval_files(metadata_dir: str):
    local_feed_path = os.path.join(metadata_dir, "feed.json")
    success = download_file(f"{OVAL_FEED_BASE_URL}feed.json", local_feed_path)
    LOGGER.info("Downloaded OVAL feed JSON, success=%s", success)

    feed = OvalFeed(local_feed_path)
    for idx, (stream_id, stream_url) in enumerate(feed.streams_url.items(), start=1):
        os.makedirs(os.path.dirname(feed.streams_local_path[stream_id]), exist_ok=True)  # Make sure subdirs exist
        success = download_file(stream_url, feed.streams_local_path[stream_id])
        LOGGER.info("Downloaded OVAL stream %s [%s/%s], success=%s", stream_id, idx, feed.streams_count, success)


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
