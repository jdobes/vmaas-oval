import argparse
import sys

from vmaas_oval.common.constants import DEFAULT_METADATA_DIR
from vmaas_oval.common.logger import get_logger
from vmaas_oval.database.schema import initialize_schema
from vmaas_oval.common.logger import init_logging

LOGGER = get_logger(__name__)


def sync_data(db_file_name: str) -> None:
    LOGGER.info("Synchronizing data in sqlite DB file: %s", db_file_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize DB schema.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--file", default="database.sqlite", help="sqlite DB file path")
    parser.add_argument("-m", "--metadata-dir", default=DEFAULT_METADATA_DIR, help="dir containing downloaded metadata")
    parser.add_argument("-s", "--schema-only", action="store_true", help="initialize only empty schema and finish")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)
    initialize_schema(args.file)

    if args.schema_only:
        sys.exit(0)
    
    sync_data(args.file)
