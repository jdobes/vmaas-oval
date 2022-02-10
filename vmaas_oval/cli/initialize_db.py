import argparse
import sys

from vmaas_oval.database_handler import initialize_schema
from vmaas_oval.sync import sync_data
from vmaas_oval.utils import init_logging


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize DB schema.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--file", default="data.sqlite", help="sqlite DB file path")
    parser.add_argument("-s", "--schema-only", action="store_true", help="initialize only empty schema and finish")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)
    initialize_schema(args.file)

    if args.schema_only:
        sys.exit(0)
    
    sync_data(args.file)
