import argparse

from vmaas_oval.common.logger import get_logger, init_logging
from vmaas_oval.database.handler import SqliteConnection
from vmaas_oval.evaluator.cache import Cache

LOGGER = get_logger(__name__)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run evaluator.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--database", default="database.sqlite", help="sqlite DB file path")
    parser.add_argument("-s", "--single-file", help="evaluate only single system profile and finish")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)
    LOGGER.info("Sqlite DB file: %s", args.database)

    with SqliteConnection(args.database) as con:
        cache = Cache(con)
