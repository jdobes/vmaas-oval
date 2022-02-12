import argparse
import os
import sys

from vmaas_oval.common.constants import DEFAULT_METADATA_DIR
from vmaas_oval.common.logger import get_logger, init_logging
from vmaas_oval.common.unpacker import unpack_file
from vmaas_oval.database.handler import SqliteConnection
from vmaas_oval.database.repo_cpe_store import RepoCpeStore
from vmaas_oval.database.schema import initialize_schema
from vmaas_oval.parsers.oval_feed import OvalFeed
from vmaas_oval.parsers.oval_stream import OvalStream
from vmaas_oval.parsers.repo_cpe_map import RepoCpeMap

LOGGER = get_logger(__name__)


def sync_repo_cpe_map(db_file_name: str, metadata_dir: str) -> None:
    LOGGER.info("Synchronizing Repository to CPE mapping")
    with SqliteConnection(db_file_name) as con:
        repo_cpe_store = RepoCpeStore(con)
        repo_cpe_map = RepoCpeMap(os.path.join(metadata_dir, "repository-to-cpe.json"), repo_cpe_store.arch_map)
        repo_cpe_store.store(repo_cpe_map)
    LOGGER.info("Synchronization of Repository to CPE mapping completed")


def sync_oval_streams(db_file_name: str, metadata_dir: str) -> None:
    LOGGER.info("Synchronizing OVAL streams")
    local_feed_path = os.path.join(metadata_dir, "feed.json")
    feed = OvalFeed(local_feed_path)
    for idx, (stream_id, stream_local_path) in enumerate(feed.streams_local_path.items(), start=1):
        try:
            LOGGER.info("Synchronizing OVAL stream: %s [%s/%s]", stream_id, idx, feed.streams_count)
            unpacked_stream_path = unpack_file(stream_local_path)
            final_stream_path = unpacked_stream_path if unpacked_stream_path else stream_local_path  # The file might be already unpacked
            oval_stream = OvalStream(stream_id, None, final_stream_path)
            oval_stream.load_metadata()
            oval_stream.unload_metadata()
        finally:
            if unpacked_stream_path:
                os.remove(unpacked_stream_path)  # Delete unpacked file, keep original archive
    LOGGER.info("Synchronization of OVAL streams completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize DB schema.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--database", default="database.sqlite", help="sqlite DB file path")
    parser.add_argument("-m", "--metadata-dir", default=DEFAULT_METADATA_DIR, help="dir containing downloaded metadata")
    parser.add_argument("-s", "--schema-only", action="store_true", help="initialize only empty schema and finish")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)
    LOGGER.info("Sqlite DB file: %s", args.database)
    initialize_schema(args.database)

    if args.schema_only:
        sys.exit(0)

    sync_repo_cpe_map(args.database, args.metadata_dir)
    sync_oval_streams(args.database, args.metadata_dir)
